package session

import "net/http"

func ExtractSessionID(r *http.Request) string {
	if uid := r.Header.Get("X-Corp-User-Id"); uid != "" {
		return uid
	}
	if cookie, err := r.Cookie("__Secure-next-auth.session-token"); err == nil {
		return cookie.Value
	}
	return r.RemoteAddr
}