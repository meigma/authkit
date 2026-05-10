package provisioning

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileConditionCachesNormalizedProgram(t *testing.T) {
	resetConditionProgramCacheForTest()

	_, err := compileCondition(" claims.repository_id == '123' ")
	require.NoError(t, err)
	_, err = compileCondition("claims.repository_id == '123'")
	require.NoError(t, err)

	conditionProgramCache.mu.RLock()
	defer conditionProgramCache.mu.RUnlock()

	require.Len(t, conditionProgramCache.programs, 1)
	_, ok := conditionProgramCache.programs["claims.repository_id == '123'"]
	assert.True(t, ok)
}

func TestCompileConditionDoesNotCacheInvalidExpressions(t *testing.T) {
	resetConditionProgramCacheForTest()

	_, err := compileCondition("claims.repository_id")
	require.Error(t, err)

	conditionProgramCache.mu.RLock()
	defer conditionProgramCache.mu.RUnlock()

	assert.Empty(t, conditionProgramCache.programs)
}

func resetConditionProgramCacheForTest() {
	conditionProgramCache.mu.Lock()
	defer conditionProgramCache.mu.Unlock()

	conditionProgramCache.programs = nil
}
