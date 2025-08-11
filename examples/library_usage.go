package main

import (
	"fmt"
	"log"

	poltergeist "github.com/ghostsecurity/poltergeist/pkg"
)

func main() {
	// Example 1: Simple usage with built-in rules
	basicExample()

	// Example 2: Advanced usage with custom configuration
	advancedExample()

	// Example 3: Using the scanner programmatically with inline rules
	inlineRulesExample()
}

// basicExample demonstrates basic library usage
func basicExample() {
	fmt.Println("=== Basic Example ===")

	// Load rules from a directory
	rules, err := poltergeist.LoadRulesFromDirectory("../rules")
	if err != nil {
		log.Printf("Warning: Could not load rules from ../rules: %v", err)
		// Fallback to a simple rule
		rules = []poltergeist.Rule{
			{
				Name:    "Simple API Key",
				ID:      "simple.api.key",
				Pattern: `[A-Za-z0-9]{32}`,
				Tags:    []string{"api-key"},
			},
		}
	}

	// Select engine automatically
	engineType := poltergeist.SelectEngine(rules, "auto")
	fmt.Printf("Selected engine: %s\n", engineType)

	// Create engine
	var engine poltergeist.PatternEngine
	if engineType == "hyperscan" {
		engine = poltergeist.NewHyperscanEngine()
	} else {
		engine = poltergeist.NewGoRegexEngine()
	}
	defer engine.Close()

	// Compile rules
	err = engine.CompileRules(rules)
	if err != nil {
		log.Fatalf("Failed to compile rules: %v", err)
	}

	// Create scanner with default settings
	scanner := poltergeist.NewScanner(engine)

	// Scan a directory (replace with actual path)
	fmt.Printf("Scanning current directory with %d rules...\n", len(rules))
	results, err := scanner.ScanDirectory(".")
	if err != nil {
		log.Printf("Scan error: %v", err)
		return
	}

	// Print results
	fmt.Printf("Found %d matches\n", len(results))
	for _, result := range results {
		fmt.Printf("  %s:%d - %s (%s)\n", result.FilePath, result.LineNumber, result.RuleName, result.RuleID)
	}

	// Print metrics
	fmt.Printf("Files scanned: %d\n", scanner.Metrics.FilesScanned)
	fmt.Printf("Files skipped: %d\n", scanner.Metrics.FilesSkipped)
	fmt.Printf("Total bytes: %s\n", poltergeist.FormatBytes(scanner.Metrics.TotalBytes))

	fmt.Println()
}

// advancedExample demonstrates advanced configuration
func advancedExample() {
	fmt.Println("=== Advanced Example ===")

	// Create custom rules
	rules := []poltergeist.Rule{
		{
			Name:    "AWS Access Key",
			ID:      "aws.access.key",
			Pattern: `AKIA[0-9A-Z]{16}`,
			Tags:    []string{"aws", "credentials"},
			Entropy: 3.0,
		},
		{
			Name:    "Private SSH Key",
			ID:      "ssh.private.key",
			Pattern: `-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----`,
			Tags:    []string{"ssh", "private-key"},
		},
	}

	// Use Go regex engine specifically
	engine := poltergeist.NewGoRegexEngine()
	defer engine.Close()

	err := engine.CompileRules(rules)
	if err != nil {
		log.Fatalf("Failed to compile rules: %v", err)
	}

	// Create scanner with custom settings
	scanner := poltergeist.NewScannerWithOptions(
		engine,
		4,            // 4 workers
		50*1024*1024, // 50MB max file size
	)

	fmt.Printf("Using %s engine with %d workers\n", engine.Name(), scanner.WorkerCount)
	fmt.Printf("Max file size: %s\n", poltergeist.FormatBytes(scanner.MaxFileSize))

	// For demo purposes, scan a small directory
	results, err := scanner.ScanDirectory(".")
	if err != nil {
		log.Printf("Scan error: %v", err)
		return
	}

	fmt.Printf("Advanced scan completed: %d results\n", len(results))
	fmt.Println()
}

// inlineRulesExample shows how to scan with programmatically created rules
func inlineRulesExample() {
	fmt.Println("=== Inline Rules Example ===")

	// Create rules programmatically (e.g., from a database or API)
	sensitivePatterns := map[string]string{
		"email":       `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
		"credit-card": `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`,
		"phone":       `\b\d{3}-\d{3}-\d{4}\b`,
	}

	var rules []poltergeist.Rule
	for name, pattern := range sensitivePatterns {
		rules = append(rules, poltergeist.Rule{
			Name:    fmt.Sprintf("Auto-generated %s pattern", name),
			ID:      fmt.Sprintf("auto.%s", name),
			Pattern: pattern,
			Tags:    []string{"auto-generated", name},
		})
	}

	// Check if hyperscan is available for multiple patterns
	if poltergeist.IsHyperscanAvailable() {
		fmt.Println("Hyperscan is available - using for multiple patterns")
	} else {
		fmt.Println("Hyperscan not available - using Go regex")
	}

	engine := poltergeist.NewGoRegexEngine() // Using Go for this example
	defer engine.Close()

	err := engine.CompileRules(rules)
	if err != nil {
		log.Fatalf("Failed to compile inline rules: %v", err)
	}

	scanner := poltergeist.NewScanner(engine)

	// Scan specific files if they exist
	testFiles := []string{".", "../README.md"}

	for _, path := range testFiles {
		fmt.Printf("Scanning: %s\n", path)
		results, err := scanner.ScanDirectory(path)
		if err != nil {
			log.Printf("Error scanning %s: %v", path, err)
			continue
		}

		if len(results) > 0 {
			fmt.Printf("  Found %d potential matches\n", len(results))
			// Limit output to first few results for demo
			for i, result := range results {
				if i >= 3 {
					fmt.Printf("  ... and %d more\n", len(results)-3)
					break
				}
				fmt.Printf("    %s:%d - %s\n", result.FilePath, result.LineNumber, result.RuleName)
			}
		} else {
			fmt.Printf("  No matches found\n")
		}
	}

	fmt.Println()
}
