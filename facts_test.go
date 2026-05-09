package authkit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/meigma/authkit"
)

func TestFactsCloneCopiesMap(t *testing.T) {
	facts := authkit.Facts{
		"tenant_id": "tenant-1",
		"approved":  true,
	}

	cloned := facts.Clone()
	cloned["tenant_id"] = "tenant-2"

	assert.Equal(t, "tenant-1", facts["tenant_id"])
	assert.Equal(t, true, cloned["approved"])
}

func TestFactsCloneReturnsNilForEmptyFacts(t *testing.T) {
	assert.Nil(t, authkit.Facts(nil).Clone())
	assert.Nil(t, authkit.Facts{}.Clone())
}

func TestMergeFactsMergesFactSets(t *testing.T) {
	merged := authkit.MergeFacts(
		nil,
		authkit.Facts{
			"tenant_id": "tenant-1",
			"approved":  false,
		},
		authkit.Facts{
			"approved": true,
			"region":   "us-west",
		},
	)

	assert.Equal(t, authkit.Facts{
		"tenant_id": "tenant-1",
		"approved":  true,
		"region":    "us-west",
	}, merged)
}

func TestMergeFactsReturnsNilForEmptyInput(t *testing.T) {
	assert.Nil(t, authkit.MergeFacts())
	assert.Nil(t, authkit.MergeFacts(nil, authkit.Facts{}))
}
