package provisioning

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	"github.com/meigma/authkit"
)

const (
	// MaxConditionBytes is the maximum UTF-8 byte length accepted for a CEL condition.
	MaxConditionBytes = 4096

	conditionCostLimit uint64 = 10_000
)

const (
	conditionInterruptCheckFrequency = 100
)

//nolint:gochecknoglobals // CEL environment construction is expensive and intentionally cached process-wide.
var conditionEnvironment struct {
	once sync.Once
	env  *cel.Env
	err  error
}

//nolint:gochecknoglobals // Compiled CEL programs are reusable and safe to share across rule evaluations.
var conditionProgramCache struct {
	mu       sync.RWMutex
	programs map[string]cel.Program
}

// NormalizeCondition returns condition trimmed of leading and trailing whitespace.
func NormalizeCondition(condition string) string {
	return strings.TrimSpace(condition)
}

// ValidateCondition compiles and type-checks condition as a CEL bool expression.
func ValidateCondition(condition string) error {
	_, err := compileCondition(condition)

	return err
}

func conditionMatches(ctx context.Context, identity authkit.Identity, condition string) bool {
	prg, err := compileCondition(condition)
	if err != nil {
		return false
	}
	claims := identity.Claims
	if claims == nil {
		claims = map[string]any{}
	}

	out, _, err := prg.ContextEval(ctx, map[string]any{
		"identity": map[string]string{
			"provider":      identity.Provider,
			"subject":       identity.Subject,
			"credential_id": identity.CredentialID,
		},
		"claims": claims,
	})
	if err != nil {
		return false
	}

	result, ok := out.Value().(bool)

	return ok && result
}

func compileCondition(condition string) (cel.Program, error) {
	condition = NormalizeCondition(condition)
	if condition == "" {
		return nil, errors.New("provisioning: condition is required")
	}
	if len(condition) > MaxConditionBytes {
		return nil, fmt.Errorf("provisioning: condition exceeds %d bytes", MaxConditionBytes)
	}
	if prg, ok := cachedConditionProgram(condition); ok {
		return prg, nil
	}

	env, err := getConditionEnv()
	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(condition)
	if issues.Err() != nil {
		return nil, fmt.Errorf("provisioning: compile condition: %w", issues.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("provisioning: condition must produce bool, got %s", ast.OutputType())
	}

	prg, err := env.Program(
		ast,
		cel.CostLimit(conditionCostLimit),
		cel.EvalOptions(cel.OptOptimize),
		cel.InterruptCheckFrequency(conditionInterruptCheckFrequency),
	)
	if err != nil {
		return nil, fmt.Errorf("provisioning: build condition program: %w", err)
	}

	return cacheConditionProgram(condition, prg), nil
}

func cachedConditionProgram(condition string) (cel.Program, bool) {
	conditionProgramCache.mu.RLock()
	defer conditionProgramCache.mu.RUnlock()

	if conditionProgramCache.programs == nil {
		return nil, false
	}

	prg, ok := conditionProgramCache.programs[condition]

	return prg, ok
}

func cacheConditionProgram(condition string, prg cel.Program) cel.Program {
	conditionProgramCache.mu.Lock()
	defer conditionProgramCache.mu.Unlock()

	if conditionProgramCache.programs == nil {
		conditionProgramCache.programs = map[string]cel.Program{}
	}
	if existing, ok := conditionProgramCache.programs[condition]; ok {
		return existing
	}

	conditionProgramCache.programs[condition] = prg

	return prg
}

func getConditionEnv() (*cel.Env, error) {
	conditionEnvironment.once.Do(func() {
		conditionEnvironment.env, conditionEnvironment.err = cel.NewEnv(
			cel.Variable("identity", cel.MapType(cel.StringType, cel.StringType)),
			cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)),
			cel.Function(
				"hasAny",
				cel.Overload(
					"has_any_dyn_list_string",
					[]*cel.Type{cel.DynType, cel.ListType(cel.StringType)},
					cel.BoolType,
					cel.BinaryBinding(func(value ref.Val, accepted ref.Val) ref.Val {
						return types.Bool(valueHasAny(value, acceptedStrings(accepted)))
					}),
				),
			),
			cel.Function(
				"hasToken",
				cel.Overload(
					"has_token_dyn_string",
					[]*cel.Type{cel.DynType, cel.StringType},
					cel.BoolType,
					cel.BinaryBinding(func(value ref.Val, token ref.Val) ref.Val {
						tokenString, ok := stringValue(token)
						if !ok || tokenString == "" {
							return types.False
						}

						return types.Bool(valueHasToken(value, tokenString))
					}),
				),
			),
		)
	})

	return conditionEnvironment.env, conditionEnvironment.err
}

func acceptedStrings(value ref.Val) map[string]struct{} {
	accepted := make(map[string]struct{})
	forEachString(value, func(item string) {
		accepted[item] = struct{}{}
	})

	return accepted
}

func valueHasAny(value ref.Val, accepted map[string]struct{}) bool {
	if len(accepted) == 0 {
		return false
	}

	matched := false
	forEachString(value, func(item string) {
		if _, ok := accepted[item]; ok {
			matched = true
		}
	})

	return matched
}

func valueHasToken(value ref.Val, token string) bool {
	matched := false
	forEachString(value, func(item string) {
		if slices.Contains(strings.Fields(item), token) {
			matched = true
		}
	})

	return matched
}

func forEachString(value ref.Val, visit func(string)) {
	if item, ok := stringValue(value); ok {
		visit(item)

		return
	}

	if list, ok := value.(traits.Lister); ok {
		iter := list.Iterator()
		for iter.HasNext() == types.True {
			if item, ok := stringValue(iter.Next()); ok {
				visit(item)
			}
		}

		return
	}

	switch native := value.Value().(type) {
	case []string:
		for _, item := range native {
			visit(item)
		}
	case []any:
		for _, item := range native {
			if text, ok := item.(string); ok {
				visit(text)
			}
		}
	case []ref.Val:
		for _, item := range native {
			if text, ok := stringValue(item); ok {
				visit(text)
			}
		}
	}
}

func stringValue(value ref.Val) (string, bool) {
	if value == nil {
		return "", false
	}

	if text, ok := value.Value().(string); ok {
		return text, true
	}

	native, err := value.ConvertToNative(reflect.TypeFor[string]())
	if err != nil {
		return "", false
	}
	text, ok := native.(string)

	return text, ok
}
