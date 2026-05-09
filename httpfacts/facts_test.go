package httpfacts_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/httpfacts"
)

func TestRequestFactHelpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/images/123", nil)
	req.Host = "api.example.test"
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.SetPathValue("imageID", "123")

	facts := authkit.MergeFacts(
		httpfacts.Method(req),
		httpfacts.Host(req),
		httpfacts.Path(req),
		httpfacts.RemoteAddr(req),
		httpfacts.Header(req, "X-Tenant-Id"),
		httpfacts.PathValue(req, "imageID"),
	)

	assert.Equal(t, authkit.Facts{
		httpfacts.MethodKey:                http.MethodPost,
		httpfacts.HostKey:                  "api.example.test",
		httpfacts.PathKey:                  "/images/123",
		httpfacts.RemoteAddrKey:            "192.0.2.10:12345",
		httpfacts.HeaderKey("X-Tenant-Id"): "tenant-1",
		httpfacts.PathValueKey("imageID"):  "123",
	}, facts)
}

func TestHelpersReturnNilForMissingRequest(t *testing.T) {
	assert.Nil(t, httpfacts.Method(nil))
	assert.Nil(t, httpfacts.Host(nil))
	assert.Nil(t, httpfacts.Path(nil))
	assert.Nil(t, httpfacts.RemoteAddr(nil))
	assert.Nil(t, httpfacts.Header(nil, "X-Tenant-Id"))
	assert.Nil(t, httpfacts.PathValue(nil, "imageID"))
}

func TestHelpersReturnNilForMissingNames(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	assert.Nil(t, httpfacts.Header(req, ""))
	assert.Nil(t, httpfacts.PathValue(req, ""))
}
