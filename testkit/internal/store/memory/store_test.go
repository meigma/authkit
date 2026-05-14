package memory_test

import (
	"testing"

	"github.com/meigma/authkit/testkit/internal/paste"
	"github.com/meigma/authkit/testkit/internal/store/memory"
	"github.com/meigma/authkit/testkit/internal/store/storetest"
)

func TestSharedStoreBehavior(t *testing.T) {
	storetest.Run(t, func(t *testing.T) paste.Repository {
		t.Helper()

		return memory.NewStore()
	})
}
