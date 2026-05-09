package authkit

import "maps"

// FactKey identifies one caller-supplied authorization fact.
type FactKey string

// Facts contains decision-time authorization context supplied by applications.
type Facts map[FactKey]any

// Clone returns a shallow copy of facts.
func (facts Facts) Clone() Facts {
	if len(facts) == 0 {
		return nil
	}

	cloned := make(Facts, len(facts))
	maps.Copy(cloned, facts)

	return cloned
}

// MergeFacts returns a shallow merge of fact sets.
//
// Later fact sets replace earlier values for the same key.
func MergeFacts(factSets ...Facts) Facts {
	var merged Facts
	for _, facts := range factSets {
		for key, value := range facts {
			if merged == nil {
				merged = make(Facts)
			}
			merged[key] = value
		}
	}

	return merged
}
