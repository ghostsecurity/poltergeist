package poltergeist

import (
	"strings"
	"testing"
)

func TestEngineCompilationErrors(t *testing.T) {
	// Test invalid regex patterns
	invalidRules := []Rule{
		{
			Name:    "Invalid Pattern",
			ID:      "test.invalid",
			Pattern: `[unclosed bracket`,
			Tags:    []string{"invalid"},
		},
	}

	// Test Go regex engine with invalid pattern
	goEngine := NewGoRegexEngine()
	defer goEngine.Close()

	err := goEngine.CompileRules(invalidRules)
	if err == nil {
		t.Error("Expected Go regex engine to fail with invalid pattern")
	}

	// Test Hyperscan engine with invalid pattern (if available)
	if IsHyperscanAvailable() {
		hsEngine := NewHyperscanEngine()
		defer hsEngine.Close()

		err = hsEngine.CompileRules(invalidRules)
		if err == nil {
			t.Error("Expected Hyperscan engine to fail with invalid pattern")
		}
	}
}

func TestEngineRedaction(t *testing.T) {
	redactionRule := []Rule{
		{
			Name:    "Redacted API Key",
			ID:      "test.redacted",
			Pattern: `secret[_-]?key['":\s=]+([a-zA-Z0-9]{20,})`,
			Redact:  []int{4, 4}, // Keep first 4 and last 4 chars
		},
	}

	engines := []PatternEngine{
		NewGoRegexEngine(),
		NewHyperscanEngine(),
	}

	for _, engine := range engines {
		defer engine.Close()

		err := engine.CompileRules(redactionRule)
		if err != nil {
			t.Fatalf("Failed to compile redaction rule: %v", err)
		}

		input := `secret_key="abcdefghijklmnopqrstuvwxyz1234"`
		results := engine.FindAllInLine(input)

		if len(results) != 1 {
			t.Fatalf("Expected 1 match for redaction test, got %d", len(results))
		}

		result := results[0]
		if result.Redacted == result.Match {
			t.Error("Expected redacted version to be different from original match")
		}

		// Should contain asterisks for redaction
		if !strings.Contains(result.Redacted, "*****") {
			t.Errorf("Expected redacted text to contain asterisk mask, got: %s", result.Redacted)
		}
	}
}

func TestEngineRedactionAlwaysRedacts(t *testing.T) {
	// Test that secrets are ALWAYS redacted, even when rule redaction can't apply
	redactionRule := []Rule{
		{
			Name:    "Redacted API Key",
			ID:      "test.redacted",
			Pattern: `secret[_-]?key['":\s=]+([a-zA-Z0-9]{20,})`,
			Redact:  []int{50, 50}, // Keep first 50 and last 50 chars (but match is shorter)
		},
	}

	engines := []PatternEngine{
		NewGoRegexEngine(),
		NewHyperscanEngine(),
	}

	for _, engine := range engines {
		defer engine.Close()

		err := engine.CompileRules(redactionRule)
		if err != nil {
			t.Fatalf("Failed to compile redaction rule: %v", err)
		}

		input := `secret_key="abcdefghijklmnopqrstuvwxyz1234"`
		results := engine.FindAllInLine(input)

		if len(results) != 1 {
			t.Fatalf("Expected 1 match for redaction test, got %d", len(results))
		}

		result := results[0]

		// Secrets must ALWAYS be redacted (fallback when rule redaction can't apply)
		if !strings.Contains(result.Redacted, "*") {
			t.Errorf("Expected redacted text to contain asterisks (secrets must always be redacted), got: %s", result.Redacted)
		}

		// Verify raw match is not exposed in redacted output
		if result.Redacted == result.Match {
			t.Errorf("Redacted output should not equal raw match - secrets must be redacted")
		}
	}
}

func TestFilterOverlappingGenericMatches(t *testing.T) {
	tests := []struct {
		name     string
		matches  []MatchResult
		expected int // expected number of results
	}{
		{
			name:     "empty matches",
			matches:  []MatchResult{},
			expected: 0,
		},
		{
			name: "single generic match - kept",
			matches: []MatchResult{
				{Start: 0, End: 10, RuleID: "ghost.generic.1"},
			},
			expected: 1,
		},
		{
			name: "single non-generic match - kept",
			matches: []MatchResult{
				{Start: 0, End: 10, RuleID: "ghost.anthropic.1"},
			},
			expected: 1,
		},
		{
			name: "overlapping generic and non-generic - generic filtered",
			matches: []MatchResult{
				{Start: 0, End: 20, RuleID: "ghost.generic.1"},
				{Start: 5, End: 15, RuleID: "ghost.anthropic.1"},
			},
			expected: 1, // only non-generic kept
		},
		{
			name: "non-overlapping generic and non-generic - both kept",
			matches: []MatchResult{
				{Start: 0, End: 10, RuleID: "ghost.generic.1"},
				{Start: 50, End: 60, RuleID: "ghost.anthropic.1"},
			},
			expected: 2,
		},
		{
			name: "multiple generics overlapping one non-generic",
			matches: []MatchResult{
				{Start: 0, End: 20, RuleID: "ghost.generic.1"},
				{Start: 5, End: 25, RuleID: "ghost.generic.2"},
				{Start: 10, End: 15, RuleID: "ghost.anthropic.1"},
			},
			expected: 1, // only non-generic kept
		},
		{
			name: "two non-generic matches - both kept",
			matches: []MatchResult{
				{Start: 0, End: 10, RuleID: "ghost.anthropic.1"},
				{Start: 5, End: 15, RuleID: "ghost.stripe.1"},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterOverlappingGenericMatches(tt.matches)
			if len(result) != tt.expected {
				t.Errorf("filterOverlappingGenericMatches() returned %d matches, expected %d", len(result), tt.expected)
			}

			// Verify no generic matches remain when non-generic overlaps
			for _, m := range result {
				if strings.HasPrefix(m.RuleID, "ghost.generic") {
					// Check if there's an overlapping non-generic in the input
					for _, orig := range tt.matches {
						if !strings.HasPrefix(orig.RuleID, "ghost.generic") {
							if m.Start < orig.End && orig.Start < m.End {
								t.Errorf("Generic match %s should have been filtered (overlaps with %s)", m.RuleID, orig.RuleID)
							}
						}
					}
				}
			}
		})
	}
}
