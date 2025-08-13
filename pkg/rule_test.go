package poltergeist

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var testRules []Rule

func TestMain(m *testing.M) {
	if err := setupTests(); err != nil {
		fmt.Printf("Test setup failed: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	os.Exit(code)
}

func setupTests() error {
	var err error

	// Load rules from the main rules directory
	testRules, err = LoadRulesFromDirectory("../rules")
	if err != nil {
		return fmt.Errorf("failed to load rules from ../rules directory: %w", err)
	}

	if len(testRules) == 0 {
		return fmt.Errorf("expected at least 1 rule from rules directory, got 0")
	}

	return nil
}

// TestRulesValidation tests that rules compile and the patterns match as expected
func TestRulesValidation(t *testing.T) {
	// Add platform info for debugging
	t.Logf("Testing on platform: %s/%s", runtime.GOOS, runtime.GOARCH)

	// Test Hyperscan availability first
	hyperscanAvailable := IsHyperscanAvailable()
	t.Logf("Hyperscan available: %v", hyperscanAvailable)

	// Track unique IDs
	seenIDs := make(map[string]bool)

	// Test each rule for compliance with all requirements
	for _, rule := range testRules {
		t.Run(rule.ID, func(t *testing.T) {
			validateRule(t, rule, seenIDs)
		})
	}
}

// validateRule validates a single rule's structure and requirements
func validateRule(t *testing.T, rule Rule, seenIDs map[string]bool) {
	// Rule must have a name
	if rule.Name == "" {
		t.Errorf("Rule %s has empty name", rule.ID)
	}

	// Rule ID must be lowercase, alphanumeric, and periods only
	if !regexp.MustCompile(`^[a-z0-9.]+$`).MatchString(rule.ID) {
		t.Errorf("Rule ID '%s' must be lowercase, alphanumeric, and periods only", rule.ID)
	}

	// Rule ID must be unique
	if rule.ID == "" {
		t.Errorf("Rule has empty ID")
		return
	}
	if seenIDs[rule.ID] {
		t.Errorf("Rule ID '%s' is not unique - found duplicate", rule.ID)
	}
	seenIDs[rule.ID] = true

	// Rule must have a description
	if rule.Description == "" {
		t.Errorf("Rule %s has empty description", rule.ID)
	}

	// Rule must have tags
	if len(rule.Tags) == 0 {
		t.Errorf("Rule %s has no tags", rule.ID)
	}

	// Rule must have a pattern
	if rule.Pattern == "" {
		t.Errorf("Rule %s has empty pattern", rule.ID)
		return
	}

	// If rule pattern starts with regex flag, it must be (?x) and no other flags
	if strings.HasPrefix(rule.Pattern, "(?") {
		// Find the end of the flags section
		flagEnd := strings.Index(rule.Pattern, ")")
		if flagEnd == -1 {
			t.Errorf("Rule %s has malformed pattern flags", rule.ID)
			return
		}

		flags := rule.Pattern[2:flagEnd] // Extract just the flag characters
		if flags != "x" {
			t.Errorf("Rule %s pattern has invalid flags '%s' - only (?x) is allowed", rule.ID, flags)
		}
	}

	// Create a per-test hyperscan engine for thread safety
	hyperscanEngine := NewHyperscanEngine()
	t.Cleanup(func() {
		hyperscanEngine.Close()
	})

	// Rule pattern must compile with Hyperscan regex engine
	if err := hyperscanEngine.CompileRules([]Rule{rule}); err != nil {
		t.Errorf("Rule %s doesn't compile with Hyperscan regex engine: %v", rule.ID, err)
		return
	}

	// Rule pattern must compile with standard Go regex engine
	pattern := NormalizeExtendedRegex(rule.Pattern)
	regex, err := regexp.Compile(pattern)
	if err != nil {
		t.Errorf("Rule %s doesn't compile with Go regex engine: %v", rule.ID, err)
		return
	}

	// Rule must have a redaction offsets
	if len(rule.Redact) != 2 {
		t.Errorf("Rule %s has invalid redaction offsets: %v", rule.ID, rule.Redact)
	}

	// Rule must have a non-zero minimum entropy
	if rule.Entropy == 0.0 {
		t.Errorf("Rule %s has zero entropy - entropy must be specified as a float", rule.ID)
	}

	// Rule must have assert test cases
	if len(rule.Tests.Assert) == 0 {
		t.Errorf("Rule %s has no assert test cases", rule.ID)
	}

	// Rule must have assert_not test cases
	if len(rule.Tests.AssertNot) == 0 {
		t.Errorf("Rule %s has no assert_not test cases", rule.ID)
	}

	// Validate assert test cases
	for i, assertCase := range rule.Tests.Assert {
		t.Run(fmt.Sprintf("assert_%d", i+1), func(t *testing.T) {
			validateAssertCase(t, rule, assertCase, i+1, hyperscanEngine, regex)
		})
	}

	// Validate assert_not test cases
	for i, assertNotCase := range rule.Tests.AssertNot {
		t.Run(fmt.Sprintf("assert_not_%d", i+1), func(t *testing.T) {
			validateAssertNotCase(t, rule, assertNotCase, i+1, hyperscanEngine, regex)
		})
	}

	// Rule must have at least one history entry
	if len(rule.History) == 0 {
		t.Errorf("Rule %s has no history entries - at least one entry is required", rule.ID)
	}
}

// validateAssertCase validates a single assert test case
func validateAssertCase(t *testing.T, rule Rule, assertCase string, caseNum int, hyperscanEngine PatternEngine, regex *regexp.Regexp) {
	// Test with Hyperscan engine
	matches := hyperscanEngine.FindAllInLine(assertCase)
	if len(matches) == 0 {
		t.Errorf("Rule %s pattern should match assert case %d, but doesn't (Hyperscan)", rule.ID, caseNum)
	}

	// Test with Go regex engine
	if !regex.MatchString(assertCase) {
		t.Errorf("Rule %s pattern should match assert case %d, but doesn't (Go)", rule.ID, caseNum)
	}

	// Rule redact offsets must be less than the length of the assert case
	if rule.Redact[0]+rule.Redact[1] >= len(assertCase) {
		t.Errorf("Rule %s sum of redaction offsets %v can't be greater than the length of the test pattern (%d)", rule.ID, rule.Redact, len(assertCase))
	}

	if len(matches) > 0 {
		// matched content entropy must be greater than or equal to rule entropy
		entropy := ShannonEntropy(matches[0].Match)
		if entropy < rule.Entropy {
			t.Errorf("Rule %s requires entropy of at least %f, but got %f from assert case %d", rule.ID, rule.Entropy, entropy, caseNum)
		}
	}
}

// validateAssertNotCase validates a single assert_not test case
func validateAssertNotCase(t *testing.T, rule Rule, assertNotCase string, caseNum int, hyperscanEngine PatternEngine, regex *regexp.Regexp) {
	// Test with Hyperscan engine
	matches := hyperscanEngine.FindAllInLine(assertNotCase)
	if len(matches) > 0 {
		// we matched, now check if the entropy is met
		entropy := ShannonEntropy(matches[0].Match)
		if entropy >= rule.Entropy {
			t.Errorf("Rule %s pattern should not match assert_not case %d with high entropy (%f >= %f), but does (Hyperscan)", rule.ID, caseNum, entropy, rule.Entropy)
		} else {
			t.Logf("Rule %s pattern should not match assert_not case %d, but does (Hyperscan)", rule.ID, caseNum)
		}
	}

	goMatches := regex.FindAllString(assertNotCase, -1)
	if len(goMatches) > 0 {
		// we matched, now check if the entropy is met
		entropy := ShannonEntropy(goMatches[0])
		if entropy >= rule.Entropy {
			t.Errorf("Rule %s pattern should not match assert_not case %d with high entropy (%f >= %f), but does (Go)", rule.ID, caseNum, entropy, rule.Entropy)
		} else {
			t.Logf("Rule %s pattern should not match assert_not case %d, but does (Go)", rule.ID, caseNum)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		entropy float64
	}{
		{input: "", entropy: 0.0},
		{input: "A", entropy: 0.0},
		{input: "AAAA", entropy: 0.0},
		{input: "aaaaabbbbcc", entropy: 1.494919},
		{input: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", entropy: 4.700440},
		{input: "abcdefghijklmnopqrstuvwxyz", entropy: 4.700440},
		{input: "0123456789", entropy: 3.321928},
		{input: "!@#$%^&*()", entropy: 3.321928},
		{input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()", entropy: 6.169925},
	}

	const tolerance = 1e-6
	for _, tt := range tests {
		entropy := ShannonEntropy(tt.input)
		if math.Abs(entropy-tt.entropy) > tolerance {
			t.Errorf("ShannonEntropy(%q) = %f; want %f", tt.input, entropy, tt.entropy)
		}
	}
}

func TestCLIPatternCreation(t *testing.T) {
	// Test that CLI patterns are created with the correct structure
	patterns := []string{"test-pattern-1", "api[_-]?key.*", "secret.*[=:].*"}

	var rules []Rule
	for i, pattern := range patterns {
		rules = append(rules, Rule{
			Name:    fmt.Sprintf("CLI Pattern %d", i+1),
			ID:      fmt.Sprintf("cli.pattern.%d", i+1),
			Pattern: pattern,
			Tags:    []string{"cli"},
		})
	}

	// Verify we have the expected number of rules
	if len(rules) != 3 {
		t.Fatalf("Expected 3 CLI rules, got %d", len(rules))
	}

	// Verify first rule
	rule1 := rules[0]
	if rule1.Name != "CLI Pattern 1" {
		t.Errorf("Expected rule name 'CLI Pattern 1', got '%s'", rule1.Name)
	}
	if rule1.ID != "cli.pattern.1" {
		t.Errorf("Expected rule ID 'cli.pattern.1', got '%s'", rule1.ID)
	}
	if rule1.Pattern != "test-pattern-1" {
		t.Errorf("Expected pattern 'test-pattern-1', got '%s'", rule1.Pattern)
	}
	if len(rule1.Tags) != 1 || rule1.Tags[0] != "cli" {
		t.Errorf("Expected tags ['cli'], got %v", rule1.Tags)
	}

	// Verify the CLI rules have the expected default values
	if rule1.Entropy != 0.0 {
		t.Errorf("Expected default entropy 0.0, got %f", rule1.Entropy)
	}
	if len(rule1.Tests.Assert) != 0 {
		t.Errorf("Expected empty assert tests, got %v", rule1.Tests.Assert)
	}
	if len(rule1.Tests.AssertNot) != 0 {
		t.Errorf("Expected empty assert_not tests, got %v", rule1.Tests.AssertNot)
	}
}
