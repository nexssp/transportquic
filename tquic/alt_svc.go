package tquic

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// AltSvcMiddleware advertises an HTTP/3 authority such as ":8443" or
// "api.example.com:8443". Invalid authorities are ignored.
func AltSvcMiddleware(authority string) func(http.Handler) http.Handler {
	value := altSvcValue(authority)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if value != "" {
				w.Header().Set("Alt-Svc", value)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func altSvcValue(authority string) string {
	if strings.ContainsAny(authority, "\"\\\r\n") {
		return ""
	}
	_, port, err := net.SplitHostPort(authority)
	if err != nil {
		return ""
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return ""
	}
	return fmt.Sprintf(`h3=%q; ma=86400`, authority)
}
