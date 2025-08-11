package poltergeist

import (
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RuleFile represents the structure of a YAML rule file
type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

// Rule represents a single pattern matching rule in the new format
type Rule struct {
	// Name is a human-readable rule name.
	Name string `yaml:"name"`

	// ID is a machine-readable identifier.
	ID string `yaml:"id"`

	// Description is a human-readable description of the rule. The
	// description content will be displayed to users
	Description string `yaml:"description"`

	// Tags are categorization tags.
	Tags []string `yaml:"tags"`

	// Pattern is a regex pattern for matching.
	Pattern string `yaml:"pattern"`

	// Redact is a list of byte offsets, between which the matched text
	// should be replaced with the redaction string to prevent leaking
	// sensitive data.
	Redact []int `yaml:"redact"`

	// Entropy is the minimum entropy threshold for matches.
	Entropy float64 `yaml:"entropy"`

	// Tests are test cases for rule validation - both positive and negative.
	Tests Test `yaml:"tests"`

	// History is a list of change history entries. (minimum one entry)
	History []string `yaml:"history"`

	// Refs are references to external resources/links supporting the secret
	// detection approach or explaining how the secret is typically used.
	Refs []string `yaml:"refs"` // optional

	// Notes are Ghost internal notes about the rule.
	Notes []string `yaml:"notes"` // optional
}

// Test represents test cases for rule validation
type Test struct {
	Assert    []string `yaml:"assert"`
	AssertNot []string `yaml:"assert_not"`
}

// RuntimeRule contains only the rule fields needed for pattern matching at runtime
type RuntimeRule struct {
	Name    string
	ID      string
	Pattern string
	Redact  []int
	Entropy float64
}

// ToRuntimeRule converts a Rule to a RuntimeRule, excluding test and history data
// to improve memory efficiency in the engine.
func (r *Rule) ToRuntimeRule() RuntimeRule {
	return RuntimeRule{
		Name:    r.Name,
		ID:      r.ID,
		Pattern: r.Pattern,
		Redact:  r.Redact,
		Entropy: r.Entropy,
	}
}

// NormalizeExtendedRegex normalizes PCRE extended regex syntax for Go regex.
// This handles the (?x) extended syntax by removing whitespace and comments
// outside of character classes.
//
// The conversion will fail if flags are combined with the extended syntax,
// but formatting tests will catch rules that are written with the correct
// syntax.
func NormalizeExtendedRegex(pattern string) string {
	// If the pattern doesn't use extended syntax, return as-is
	if !strings.Contains(pattern, "(?x)") {
		return pattern
	}

	// Remove the (?x) flag first
	pattern = strings.ReplaceAll(pattern, "(?x)", "")

	// Parse the pattern character by character to properly handle whitespace removal
	var result strings.Builder
	inCharClass := false
	inEscape := false

	for i, r := range pattern {
		switch {
		case inEscape:
			// Previous character was a backslash, include this character as-is
			result.WriteRune(r)
			inEscape = false

		case r == '\\':
			// Start of an escape sequence
			result.WriteRune(r)
			inEscape = true

		case r == '[' && !inCharClass:
			// Entering a character class
			result.WriteRune(r)
			inCharClass = true

		case r == ']' && inCharClass:
			// Exiting a character class
			result.WriteRune(r)
			inCharClass = false

		case inCharClass:
			// Inside character class, preserve all characters including whitespace
			result.WriteRune(r)

		case r == '#' && !inCharClass:
			// Comment outside character class - skip until end of line
			for j := i + 1; j < len(pattern); j++ {
				if pattern[j] == '\n' || pattern[j] == '\r' {
					break
				}
			}

		case unicode.IsSpace(r) && !inCharClass:
			// Whitespace outside character class - skip it
			continue

		default:
			// Regular character outside character class
			result.WriteRune(r)
		}
	}

	return result.String()
}

// ShannonEntropy calculates the entropy of a string using the Shannon entropy formula
func ShannonEntropy(s string) float64 {
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	entropy := 0.0
	totalRunes := utf8.RuneCountInString(s)

	for _, count := range counts {
		p := float64(count) / float64(totalRunes)
		entropy -= p * math.Log2(p)
	}

	return entropy
}
