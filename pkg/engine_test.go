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

func TestEngineRedactionDoesntPanic(t *testing.T) {
	redactionRule := []Rule{
		{
			Name:    "Redacted API Key",
			ID:      "test.redacted",
			Pattern: `secret[_-]?key['":\s=]+([a-zA-Z0-9]{20,})`,
			Redact:  []int{50, 50}, // Keep first 50 and last 50 chars
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

		// Should not contain asterisks for redaction, because the match is too short
		if strings.Contains(result.Redacted, "*****") {
			t.Errorf("Expected redacted text to not contain asterisk mask, got: %s", result.Redacted)
		}
	}
}
