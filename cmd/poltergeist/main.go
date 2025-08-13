package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	poltergeist "github.com/ghostsecurity/poltergeist/pkg"
)

// printUsage displays the command usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <directory_path|file_path> [pattern1] [pattern2] ...\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	fmt.Fprintf(os.Stderr, "  -engine string\n")
	fmt.Fprintf(os.Stderr, "        Pattern engine: 'auto' (default), 'go', or 'hyperscan'\n")
	fmt.Fprintf(os.Stderr, "  -rules string\n")
	fmt.Fprintf(os.Stderr, "        YAML file or directory containing pattern rules (optional - uses built-in rules if not specified)\n")
	fmt.Fprintf(os.Stderr, "  -dnr\n")
	fmt.Fprintf(os.Stderr, "        Do not redact - show full matches instead of redacted versions\n")
	fmt.Fprintf(os.Stderr, "  -low-entropy\n")
	fmt.Fprintf(os.Stderr, "        Show matches that don't meet minimum entropy requirements\n")
	fmt.Fprintf(os.Stderr, "  -help\n")
	fmt.Fprintf(os.Stderr, "        Show this help message\n")
	fmt.Fprintf(os.Stderr, "  -version\n")
	fmt.Fprintf(os.Stderr, "        Show version information\n")
	fmt.Fprintf(os.Stderr, "\nIf no rules are specified via -rules flag or command-line patterns,\n")
	fmt.Fprintf(os.Stderr, "the tool will use built-in detection rules for common secrets.\n")
	fmt.Fprintf(os.Stderr, "\nBy default, only matches that meet minimum entropy requirements are shown.\n")
	fmt.Fprintf(os.Stderr, "Use --show-low-entropy to see all matches including low-entropy false positives.\n")
}

// Version information (set by build)
var version = "dev"

// Command-line flags
var (
	engineFlag     = flag.String("engine", "auto", "Pattern engine to use: 'auto', 'go' for Go regex, 'hyperscan' for Hyperscan/Vectorscan")
	rulesFlag      = flag.String("rules", "", "YAML file or directory containing pattern rules")
	dnrFlag        = flag.Bool("dnr", false, "Do not redact - show full matches instead of redacted versions")
	lowEntropyFlag = flag.Bool("low-entropy", false, "Show matches that don't meet minimum entropy requirements")
	helpFlag       = flag.Bool("help", false, "Show help message")
	versionFlag    = flag.Bool("version", false, "Show version information")
)

func main() {
	flag.Parse()

	if *helpFlag {
		printUsage()
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Printf("Poltergeist Secret Scanner %s\n", version)
		os.Exit(0)
	}

	// Determine scan path
	var scanPath string
	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}
	scanPath = flag.Arg(0)

	// Collect rules from various sources
	var rules []poltergeist.Rule
	var err error

	// Load rules from YAML file or directory if specified
	if *rulesFlag != "" {
		yamlRules, err := poltergeist.LoadRules(*rulesFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load rules: %v\n", err)
			os.Exit(1)
		}
		rules = append(rules, yamlRules...)
	}

	// Add command-line patterns as rules
	for i := 1; i < flag.NArg(); i++ {
		pattern := flag.Arg(i)
		rules = append(rules, poltergeist.Rule{
			Name:    fmt.Sprintf("CLI Pattern %d", i),
			ID:      fmt.Sprintf("cli.pattern.%d", i),
			Pattern: pattern,
			Tags:    []string{"cli"},
		})
	}

	// If no rules specified from file or command line, use default rules
	if len(rules) == 0 {
		defaultRules, err := poltergeist.LoadDefaultRules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load default rules: %v\n", err)
			os.Exit(1)
		}
		rules = append(rules, defaultRules...)
		fmt.Printf("Using built-in rules (%d patterns loaded)\n", len(defaultRules))
	}

	// Ensure we have at least one rule
	if len(rules) == 0 {
		fmt.Fprintf(os.Stderr, "No patterns available. This should not happen with default rules.\n")
		os.Exit(1)
	}

	// Select appropriate engine
	selectedEngine := poltergeist.SelectEngine(rules, *engineFlag)

	// Create the engine
	var engine poltergeist.PatternEngine
	switch selectedEngine {
	case "go":
		engine = poltergeist.NewGoRegexEngine()
	case "hyperscan":
		engine = poltergeist.NewHyperscanEngine()
	default:
		fmt.Fprintf(os.Stderr, "Invalid engine: %s\n", selectedEngine)
		os.Exit(1)
	}

	// Compile all rules
	err = engine.CompileRules(rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compile rules with %s engine: %v\n", engine.Name(), err)
		os.Exit(1)
	}

	// Ensure engine cleanup
	defer engine.Close()

	// Create scanner with optimized settings
	scanner := poltergeist.NewScannerWithOptions(engine, runtime.NumCPU()*2, 100*1024*1024)
	scanner.DisableRedaction = *dnrFlag

	fmt.Printf("Starting secret scan with %d workers using %s engine...\n", scanner.WorkerCount, engine.Name())
	fmt.Printf("Scanning: %s\n", scanPath)
	fmt.Printf("Rules loaded: %d patterns\n", len(rules))
	for _, rule := range rules {
		fmt.Printf("  - %s (ID: %s)\n", rule.Name, rule.ID)
	}

	fmt.Println()

	start := time.Now()
	results, err := scanner.ScanDirectory(scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}
	duration := time.Since(start)

	// Filter results based on entropy if flag is not set
	var filteredResults []poltergeist.ScanResult
	var lowEntropyCount int

	for _, result := range results {
		if result.Entropy || *lowEntropyFlag {
			filteredResults = append(filteredResults, result)
		} else {
			lowEntropyCount++
		}
	}

	// Print results
	if len(filteredResults) == 0 {
		if lowEntropyCount > 0 {
			fmt.Printf("No high-entropy matches found. %d low-entropy matches were filtered out.\n", lowEntropyCount)
			fmt.Printf("Use --show-low-entropy to see all matches.\n")
		} else {
			fmt.Println("No matches found.")
		}
	} else {
		totalMatches := len(results)
		shownMatches := len(filteredResults)
		if lowEntropyCount > 0 {
			fmt.Printf("Found %d matches (%d high-entropy, %d low-entropy filtered out):\n\n", totalMatches, shownMatches, lowEntropyCount)
		} else {
			fmt.Printf("Found %d matches:\n\n", shownMatches)
		}
		for _, result := range filteredResults {
			fmt.Printf("Rule: %s\n", result.RuleName)
			if result.RuleID != "" {
				fmt.Printf("ID: %s\n", result.RuleID)
			}
			fmt.Printf("File: %s:%d\n", result.FilePath, result.LineNumber)
			// Display either redacted or full match based on -dnr flag
			if *dnrFlag {
				fmt.Printf("Match: %s\n", result.Match)
			} else {
				fmt.Printf("Match: %s\n", result.Redacted)
			}
			// Display entropy status
			if result.Entropy {
				fmt.Printf("Entropy: ✓ Met minimum requirement\n")
			} else {
				fmt.Printf("Entropy: ✗ Below minimum requirement\n")
			}
			fmt.Println(strings.Repeat("-", 80))
		}
	}

	// Display metrics
	filesScanned := atomic.LoadInt64(&scanner.Metrics.FilesScanned)
	filesSkipped := atomic.LoadInt64(&scanner.Metrics.FilesSkipped)
	totalBytes := atomic.LoadInt64(&scanner.Metrics.TotalBytes)
	matchesFound := atomic.LoadInt64(&scanner.Metrics.MatchesFound)

	fmt.Printf("\n=== Scan Metrics ===\n")
	fmt.Printf("Files scanned: %d\n", filesScanned)
	fmt.Printf("Files skipped: %d (binary/large files)\n", filesSkipped)
	fmt.Printf("Total content: %s\n", poltergeist.FormatBytes(totalBytes))
	fmt.Printf("Total matches found: %d\n", matchesFound)
	if lowEntropyCount > 0 {
		fmt.Printf("High-entropy matches: %d\n", len(filteredResults))
		fmt.Printf("Low-entropy matches filtered: %d\n", lowEntropyCount)
	}
	fmt.Printf("Scan completed in %v\n", duration)
}
