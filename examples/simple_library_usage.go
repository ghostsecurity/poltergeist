package main

import (
	"fmt"
	"log"

	poltergeist "github.com/ghostsecurity/poltergeist/pkg"
)

// This example demonstrates how another Go program can easily use the poltergeist
// package with embedded default rules, requiring no external rule files.
func main() {
	fmt.Println("=== Simple Library Usage Example ===")

	// Load the built-in default rules - no external files needed!
	rules, err := poltergeist.LoadDefaultRules()
	if err != nil {
		log.Fatalf("Failed to load default rules: %v", err)
	}

	fmt.Printf("✅ Loaded %d default rules from embedded package data\n", len(rules))
	fmt.Printf("📦 No external rule files required!\n\n")

	// Show some example rules
	fmt.Printf("Example rules included:\n")
	for i, rule := range rules {
		if i >= 8 {
			fmt.Printf("  ... and %d more\n", len(rules)-i)
			break
		}
		fmt.Printf("  - %s\n", rule.Name)
	}

	// The rest is standard poltergeist usage
	engineType := poltergeist.SelectEngine(rules, "auto")

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

	// Create scanner
	scanner := poltergeist.NewScanner(engine)

	fmt.Printf("\n✅ Scanner ready with %s engine\n", engine.Name())
	fmt.Printf("✅ Ready to scan files/directories with %d built-in detection rules\n", len(rules))
	fmt.Printf("📊 Scanner configured with %d workers\n", scanner.WorkerCount)
	fmt.Printf("\nThis program can now scan for secrets without any external dependencies!\n")
}
