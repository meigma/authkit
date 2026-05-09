// Package httpfacts provides opt-in helpers for deriving authorization facts
// from net/http requests.
package httpfacts

import (
	"net/http"
	"strings"

	"github.com/meigma/authkit"
)

const (
	// MethodKey identifies the request method fact.
	MethodKey authkit.FactKey = "http.method"

	// HostKey identifies the request host fact.
	HostKey authkit.FactKey = "http.host"

	// PathKey identifies the request path fact.
	PathKey authkit.FactKey = "http.path"

	// RemoteAddrKey identifies the request remote address fact.
	RemoteAddrKey authkit.FactKey = "http.remote_addr"
)

// Method returns the request method fact.
func Method(req *http.Request) authkit.Facts {
	if req == nil {
		return nil
	}

	return authkit.Facts{MethodKey: req.Method}
}

// Host returns the request host fact.
func Host(req *http.Request) authkit.Facts {
	if req == nil {
		return nil
	}

	return authkit.Facts{HostKey: req.Host}
}

// Path returns the request URL path fact.
func Path(req *http.Request) authkit.Facts {
	if req == nil || req.URL == nil {
		return nil
	}

	return authkit.Facts{PathKey: req.URL.Path}
}

// RemoteAddr returns the request remote address fact.
func RemoteAddr(req *http.Request) authkit.Facts {
	if req == nil {
		return nil
	}

	return authkit.Facts{RemoteAddrKey: req.RemoteAddr}
}

// Header returns a fact for the selected request header.
func Header(req *http.Request, name string) authkit.Facts {
	if req == nil || name == "" {
		return nil
	}

	return authkit.Facts{HeaderKey(name): req.Header.Get(name)}
}

// HeaderKey returns the fact key for name.
func HeaderKey(name string) authkit.FactKey {
	return authkit.FactKey("http.header." + strings.ToLower(http.CanonicalHeaderKey(name)))
}

// PathValue returns a fact for the selected request path value.
func PathValue(req *http.Request, name string) authkit.Facts {
	if req == nil || name == "" {
		return nil
	}

	return authkit.Facts{PathValueKey(name): req.PathValue(name)}
}

// PathValueKey returns the fact key for name.
func PathValueKey(name string) authkit.FactKey {
	return authkit.FactKey("http.path_value." + name)
}
