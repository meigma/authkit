package memory

import (
	"testing"

	"github.com/meigma/authkit/internal/storetest"
)

func TestSharedStoreBehavior(t *testing.T) {
	storetest.Run(t, func(t *testing.T) storetest.Store {
		t.Helper()

		return NewStore()
	})
}
