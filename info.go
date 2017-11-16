package osin

import (
	"net/http"
	"time"
)

// InfoRequest is a request for information about some AccessData
type InfoRequest struct {
	Code       string     // Code to look up
	AccessData AccessData // AccessData associated with Code
}

// HandleInfoRequest is an http.HandlerFunc for server information
// NOT an RFC specification.
func (s *Server) HandleInfoRequest(w *Response, r *http.Request) *InfoRequest {
	r.ParseForm()
	bearer := CheckBearerAuth(r)
	if bearer == nil {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	// generate info request
	ret := &InfoRequest{
		Code: bearer.Code,
	}

	if ret.Code == "" {
		w.SetError(E_INVALID_REQUEST, "")
		return nil
	}

	var err error

	// load access data
	ret.AccessData, err = w.Storage.LoadAccess(ret.Code)
	if err != nil {
		w.SetError(E_INVALID_REQUEST, "")
		w.InternalError = err
		return nil
	}
	if ret.AccessData == nil {
		w.SetError(E_INVALID_REQUEST, "")
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
	if IsExpiredAt(ret.AccessData, s.Now()) {
		w.SetError(E_INVALID_GRANT, "")
		return nil
	}

	return ret
}

// FinishInfoRequest finalizes the request handled by HandleInfoRequest
func (s *Server) FinishInfoRequest(w *Response, r *http.Request, ir *InfoRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// output data
	w.Output["client_id"] = ir.AccessData.GetClient().GetId()
	w.Output["access_token"] = ir.AccessData.GetAccessToken()
	w.Output["token_type"] = s.Config.TokenType
	w.Output["expires_in"] = ir.AccessData.GetCreatedAt().Add(time.Duration(ir.AccessData.GetExpiresIn())*time.Second).Sub(s.Now()) / time.Second
	if ir.AccessData.GetRefreshToken() != "" {
		w.Output["refresh_token"] = ir.AccessData.GetRefreshToken()
	}
	if ir.AccessData.GetScope() != "" {
		w.Output["scope"] = ir.AccessData.GetScope()
	}
}
