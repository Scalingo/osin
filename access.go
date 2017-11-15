package osin

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// AccessRequestType is the type for OAuth param `grant_type`
type AccessRequestType string

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN      AccessRequestType = "refresh_token"
	PASSWORD           AccessRequestType = "password"
	CLIENT_CREDENTIALS AccessRequestType = "client_credentials"
	ASSERTION          AccessRequestType = "assertion"
	IMPLICIT           AccessRequestType = "__implicit"
)

// AccessRequest is a request for access tokens
type AccessRequest struct {
	Type          AccessRequestType
	Code          string
	Client        Client
	AuthorizeData AuthorizeData
	AccessData    AccessData

	// Force finish to use this access data, to allow access data reuse
	ForceAccessData AccessData
	RedirectUri     string
	Scope           string
	Username        string
	Password        string
	AssertionType   string
	Assertion       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default
	Expiration int32

	// Set if a refresh token should be generated
	GenerateRefresh bool

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request

	// Optional code_verifier as described in rfc7636
	CodeVerifier string
}

// AccessData represents an access grant (tokens, expiration, client, etc)
type AccessData interface {
	// Client information
	GetClient() Client

	// Authorize data, for authorization code
	GetAuthorizeData() AuthorizeData

	// Previous access data, for refresh token
	GetAccessData() AccessData

	// Access token
	GetAccessToken() string

	// Refresh Token. Can be blank
	GetRefreshToken() string

	// Token expiration in seconds
	GetExpiresIn() int32

	// Requested scope
	GetScope() string

	// Redirect Uri from request
	GetRedirectUri() string

	// Date created
	GetCreatedAt() time.Time

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// AccessData represents an access grant (tokens, expiration, client, etc)
type DefaultAccessData struct {
	Client        Client
	AuthorizeData AuthorizeData
	AccessData    AccessData
	AccessToken   string
	RefreshToken  string
	ExpiresIn     int32
	Scope         string
	RedirectUri   string
	CreatedAt     time.Time
	UserData      interface{}
}

func (d *DefaultAccessData) GetClient() Client               { return d.Client }
func (d *DefaultAccessData) GetAuthorizeData() AuthorizeData { return d.AuthorizeData }
func (d *DefaultAccessData) GetAccessData() AccessData       { return d.AccessData }
func (d *DefaultAccessData) GetAccessToken() string          { return d.AccessToken }
func (d *DefaultAccessData) GetRefreshToken() string         { return d.RefreshToken }
func (d *DefaultAccessData) GetExpiresIn() int32             { return d.ExpiresIn }
func (d *DefaultAccessData) GetScope() string                { return d.Scope }
func (d *DefaultAccessData) GetRedirectUri() string          { return d.RedirectUri }
func (d *DefaultAccessData) GetCreatedAt() time.Time         { return d.CreatedAt }
func (d *DefaultAccessData) GetUserData() interface{}        { return d.UserData }

// AccessTokenGen generates access tokens
type AccessTokenGen interface {
	GenerateAccessToken(data AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// HandleAccessRequest is the http.HandlerFunc for handling access token requests
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// Only allow GET or POST
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			w.SetError(E_INVALID_REQUEST, "")
			w.InternalError = errors.New("Request must be POST")
			return nil
		}
	} else if r.Method != "POST" {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Request must be POST")
		return nil
	}

	err := r.ParseForm()
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}

	grantType := AccessRequestType(r.Form.Get("grant_type"))
	if s.Config.AllowedAccessTypes.Exists(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAuthorizationCodeRequest(w, r)
		case REFRESH_TOKEN:
			return s.handleRefreshTokenRequest(w, r)
		case PASSWORD:
			return s.handlePasswordRequest(w, r)
		case CLIENT_CREDENTIALS:
			return s.handleClientCredentialsRequest(w, r)
		case ASSERTION:
			return s.handleAssertionRequest(w, r)
		}
	}

	w.SetError(E_UNSUPPORTED_GRANT_TYPE, "")
	return nil
}

func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.Form.Get("code"),
		CodeVerifier:    r.Form.Get("code_verifier"),
		RedirectUri:     r.Form.Get("redirect_uri"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "code" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid authorization code
	var err error
	ret.AuthorizeData, err = w.Storage.LoadAuthorize(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AuthorizeData.GetClient() == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AuthorizeData.GetClient().GetRedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if IsExpiredAt(ret.AuthorizeData, s.Now()) {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// code must be from the client
	if ret.AuthorizeData.GetClient().GetId() != ret.Client.GetId() {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// check redirect uri
	if ret.RedirectUri == "" {
		ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)
	}
	if err = ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.RedirectUriSeparator); err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AuthorizeData.GetRedirectUri() != ret.RedirectUri {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = errors.New("Redirect uri is different")
		return nil
	}

	// Verify PKCE, if present in the authorization data
	if len(ret.AuthorizeData.GetCodeChallenge()) > 0 {
		// https://tools.ietf.org/html/rfc7636#section-4.1
		if matched := pkceMatcher.MatchString(ret.CodeVerifier); !matched {
			w.SetError(E_INVALID_REQUEST, "code_verifier invalid (rfc7636)")
			w.InternalError = errors.New("code_verifier has invalid format")
			return nil
		}

		// https: //tools.ietf.org/html/rfc7636#section-4.6
		codeVerifier := ""
		switch ret.AuthorizeData.GetCodeChallengeMethod() {
		case "", PKCE_PLAIN:
			codeVerifier = ret.CodeVerifier
		case PKCE_S256:
			hash := sha256.Sum256([]byte(ret.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			w.SetError(E_INVALID_REQUEST, "code_challenge_method transform algorithm not supported (rfc7636)")
			return nil
		}
		if codeVerifier != ret.AuthorizeData.GetCodeChallenge() {
			w.SetError(E_INVALID_GRANT, "code_verifier invalid (rfc7636)")
			w.InternalError = errors.New("code_verifier failed comparison with code_challenge")
			return nil
		}
	}

	// set rest of data
	ret.Scope = ret.AuthorizeData.GetScope()
	ret.UserData = ret.AuthorizeData.GetUserData()

	return ret
}

func extraScopes(access_scopes, refresh_scopes string) bool {
	access_scopes_list := strings.Split(access_scopes, " ")
	refresh_scopes_list := strings.Split(refresh_scopes, " ")

	access_map := make(map[string]int)

	for _, scope := range access_scopes_list {
		if scope == "" {
			continue
		}
		access_map[scope] = 1
	}

	for _, scope := range refresh_scopes_list {
		if scope == "" {
			continue
		}
		if _, ok := access_map[scope]; !ok {
			return true
		}
	}
	return false
}

func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.Form.Get("refresh_token"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "refresh_token" is required
	if ret.Code == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// must be a valid refresh code
	var err error
	ret.AccessData, err = w.Storage.LoadRefresh(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_GRANT, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.GetClient() == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	if ret.AccessData.GetClient().GetRedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	// client must be the same as the previous token
	if ret.AccessData.GetClient().GetId() != ret.Client.GetId() {
		w.SetError(E_INVALID_CLIENT, "")
		w.InternalError = errors.New("Client id must be the same from previous token")
		return nil

	}

	// set rest of data
	ret.RedirectUri = ret.AccessData.GetRedirectUri()
	ret.UserData = ret.AccessData.GetUserData()
	if ret.Scope == "" {
		ret.Scope = ret.AccessData.GetScope()
	}

	if extraScopes(ret.AccessData.GetScope(), ret.Scope) {
		w.SetError(E_ACCESS_DENIED, "")
		w.InternalError = errors.New("the requested scope must not include any scope not originally granted by the resource owner")
		return nil
	}

	return ret
}

func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.Form.Get("username"),
		Password:        r.Form.Get("password"),
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: true,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "username" and "password" is required
	if ret.Username == "" || ret.Password == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)

	return ret
}

func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
		Scope:           r.Form.Get("scope"),
		GenerateRefresh: false,
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)

	return ret
}

func (s *Server) handleAssertionRequest(w *Response, r *http.Request) *AccessRequest {
	// get client authentication
	auth := getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}

	// generate access token
	ret := &AccessRequest{
		Type:            ASSERTION,
		Scope:           r.Form.Get("scope"),
		AssertionType:   r.Form.Get("assertion_type"),
		Assertion:       r.Form.Get("assertion"),
		GenerateRefresh: false, // assertion should NOT generate a refresh token, per the RFC
		Expiration:      s.Config.AccessExpiration,
		HttpRequest:     r,
	}

	// "assertion_type" and "assertion" is required
	if ret.AssertionType == "" || ret.Assertion == "" {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	// must have a valid client
	if ret.Client = getClient(auth, w.Storage, w); ret.Client == nil {
		return nil
	}

	// set redirect uri
	ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)

	return ret
}

func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}
	redirectUri := r.Form.Get("redirect_uri")
	// Get redirect uri from AccessRequest if it's there (e.g., refresh token request)
	if ar.RedirectUri != "" {
		redirectUri = ar.RedirectUri
	}
	if ar.Authorized {
		var ret AccessData
		var err error
		var accessToken, refreshToken string

		if ar.ForceAccessData == nil {
			ret2 := &DefaultAccessData{
				Client:        ar.Client,
				AuthorizeData: ar.AuthorizeData,
				AccessData:    ar.AccessData,
				RedirectUri:   redirectUri,
				CreatedAt:     s.Now(),
				ExpiresIn:     ar.Expiration,
				UserData:      ar.UserData,
				Scope:         ar.Scope,
			}
			// generate access token
			accessToken, refreshToken, err = s.AccessTokenGen.GenerateAccessToken(ret2, ar.GenerateRefresh)
			if err != nil {
				w.SetError(E_SERVER_ERROR, "")
				w.InternalError = err
				return
			}
			ret2.AccessToken = accessToken
			ret2.RefreshToken = refreshToken
			ret = ret2
		} else {
			ret = ar.ForceAccessData
		}

		// save access token
		if err = w.Storage.SaveAccess(ret); err != nil {
			w.SetError(E_SERVER_ERROR, "")
			w.InternalError = err
			return
		}

		// remove authorization token
		if ret.GetAuthorizeData() != nil {
			w.Storage.RemoveAuthorize(ret.GetAuthorizeData().GetCode())
		}

		// remove previous access token
		if ret.GetAccessData() != nil && !s.Config.RetainTokenAfterRefresh {
			if ret.GetAccessData().GetRefreshToken() != "" {
				w.Storage.RemoveRefresh(ret.GetAccessData().GetRefreshToken())
			}
			w.Storage.RemoveAccess(ret.GetAccessData().GetAccessToken())
		}

		// output data
		w.Output["access_token"] = ret.GetAccessToken()
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = ret.GetExpiresIn()
		if ret.GetRefreshToken() != "" {
			w.Output["refresh_token"] = ret.GetRefreshToken()
		}
		if ret.GetScope() != "" {
			w.Output["scope"] = ret.GetScope()
		}
	} else {
		w.SetError(E_ACCESS_DENIED, "")
	}
}

// Helper Functions

// getClient looks up and authenticates the basic auth using the given
// storage. Sets an error on the response if auth fails or a server error occurs.
func getClient(auth *BasicAuth, storage Storage, w *Response) Client {
	client, err := storage.GetClient(auth.Username)
	if err != nil {
		w.SetError(E_SERVER_ERROR, "")
		w.InternalError = err
		return nil
	}
	if client == nil {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	if !CheckClientSecret(client, auth.Password) {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}

	if client.GetRedirectUri() == "" {
		w.SetError(E_UNAUTHORIZED_CLIENT, "")
		return nil
	}
	return client
}
