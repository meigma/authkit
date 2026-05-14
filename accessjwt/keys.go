package accessjwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func signatureAlgorithms(names []string) (map[string]jwa.SignatureAlgorithm, error) {
	if len(names) == 0 {
		names = []string{DefaultAlgorithm}
	}

	algorithmMap := make(map[string]jwa.SignatureAlgorithm, len(names))
	for i, name := range names {
		algorithm, err := signatureAlgorithm(name)
		if err != nil {
			return nil, fmt.Errorf("accessjwt: allowed algorithm %d: %w", i, err)
		}
		if _, ok := algorithmMap[algorithm.String()]; ok {
			continue
		}

		algorithmMap[algorithm.String()] = algorithm
	}

	return algorithmMap, nil
}

func signatureAlgorithm(name string) (jwa.SignatureAlgorithm, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return jwa.EmptySignatureAlgorithm(), errors.New("signing algorithm is required")
	}
	if trimmed != name {
		return jwa.EmptySignatureAlgorithm(), errors.New("signing algorithm must not contain surrounding whitespace")
	}

	algorithm, ok := jwa.LookupSignatureAlgorithm(trimmed)
	if !ok || algorithm == jwa.EmptySignatureAlgorithm() || algorithm == jwa.NoSignature() {
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("unsupported signing algorithm %q", trimmed)
	}
	if algorithm.IsSymmetric() {
		return jwa.EmptySignatureAlgorithm(), fmt.Errorf("symmetric signing algorithm %q is not supported", trimmed)
	}

	return algorithm, nil
}

func validateKeySet(set jwk.Set, allowed map[string]jwa.SignatureAlgorithm) error {
	for index := range set.Len() {
		key, ok := set.Key(index)
		if !ok || key == nil {
			return fmt.Errorf("accessjwt: key set entry %d is required", index)
		}
		if err := validateKeyID(fmt.Sprintf("key set entry %d", index), key); err != nil {
			return err
		}
		algorithm, ok := key.Algorithm()
		if !ok {
			return fmt.Errorf("accessjwt: key set entry %d algorithm is required", index)
		}
		signatureAlgorithm, ok := algorithm.(jwa.SignatureAlgorithm)
		if !ok {
			return fmt.Errorf("accessjwt: key set entry %d algorithm must be a signature algorithm", index)
		}
		if _, ok := allowed[signatureAlgorithm.String()]; !ok {
			return fmt.Errorf(
				"accessjwt: key set entry %d algorithm %q is not allowed",
				index,
				signatureAlgorithm.String(),
			)
		}
	}

	return nil
}

func validateKeyID(name string, key jwk.Key) error {
	keyID, ok := key.KeyID()
	if !ok || strings.TrimSpace(keyID) == "" {
		return fmt.Errorf("accessjwt: %s kid is required", name)
	}
	if strings.TrimSpace(keyID) != keyID {
		return fmt.Errorf("accessjwt: %s kid must not contain surrounding whitespace", name)
	}

	return nil
}

func validateOptionalKeyAlgorithm(name string, key jwk.Key, expected jwa.SignatureAlgorithm) error {
	keyAlgorithm, ok := key.Algorithm()
	if !ok {
		return nil
	}

	signatureAlgorithm, ok := keyAlgorithm.(jwa.SignatureAlgorithm)
	if !ok {
		return fmt.Errorf("accessjwt: %s algorithm must be a signature algorithm", name)
	}
	if signatureAlgorithm.String() != expected.String() {
		return fmt.Errorf(
			"accessjwt: %s algorithm %q does not match %q",
			name,
			signatureAlgorithm.String(),
			expected.String(),
		)
	}

	return nil
}
