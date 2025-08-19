package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	poltergeist "github.com/ghostsecurity/poltergeist/pkg"
)

// BenchmarkResult holds the results of a single benchmark run
type BenchmarkResult struct {
	Engine          string
	RuleCount       int
	FilesScanned    int64
	FilesSkipped    int64
	TotalBytes      int64
	MatchesFound    int64
	ScanDuration    time.Duration
	CompileDuration time.Duration
	ThroughputMBPS  float64
}

func main() {
	// Define command line flags
	engine := flag.String("engine", "all", "Engine to benchmark: go, hyperscan, or all")
	maxRules := flag.Int("max-rules", 0, "Maximum number of rules to test (0 = no limit)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nBenchmark the Poltergeist secret scanning engine\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Validate engine argument
	if *engine != "go" && *engine != "hyperscan" && *engine != "all" {
		fmt.Fprintf(os.Stderr, "Error: invalid engine '%s'. Must be 'go', 'hyperscan', or 'all'\n", *engine)
		flag.Usage()
		os.Exit(1)
	}

	// For the results referenced in the README.md, we symlinked the Linux
	// kernel source code to `testdata/benchmark` directory and seeded some
	// secrets. This is about 1.4GB of content.
	benchmarkDir := "./pkg/testdata/benchmark/"
	rulesDir := "./rules"

	// Check if benchmark directory exists
	if _, err := os.Stat(benchmarkDir); os.IsNotExist(err) {
		log.Fatalf("Benchmark directory %s does not exist", benchmarkDir)
	}

	// Check if rules directory exists
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		log.Fatalf("Rules directory %s does not exist", rulesDir)
	}

	fmt.Println("=== Poltergeist Benchmark Tool ===")
	fmt.Printf("Benchmark Directory: %s\n", benchmarkDir)
	fmt.Printf("Rules Directory: %s\n\n", rulesDir)

	// Load packaged rules
	packagedRules, err := poltergeist.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		log.Fatalf("Failed to load packaged rules: %v", err)
	}

	fmt.Printf("Loaded %d packaged rules\n\n", len(packagedRules))

	// Test scenarios: packaged rules + dummy rule counts
	scenarios := []int{0, 10, 50, 100, 200, 500, 1000}
	var allResults []BenchmarkResult

	for _, dummyCount := range scenarios {
		// Create rule set for this scenario
		var ruleSet []poltergeist.Rule
		if dummyCount == 0 {
			ruleSet = packagedRules
		} else {
			ruleSet = append([]poltergeist.Rule{}, packagedRules...)
			dummyRules := generateDummyRules(dummyCount)
			ruleSet = append(ruleSet, dummyRules...)
		}

		// Skip scenario if it exceeds max rules limit
		if *maxRules > 0 && len(ruleSet) > *maxRules {
			if dummyCount == 0 {
				fmt.Printf("=== Skipping %d packaged rules (exceeds max-rules=%d) ===\n", len(packagedRules), *maxRules)
			} else {
				fmt.Printf("=== Skipping %d packaged + %d dummy rules (%d total, exceeds max-rules=%d) ===\n",
					len(packagedRules), dummyCount, len(ruleSet), *maxRules)
			}
			fmt.Println()
			continue
		}

		// Print scenario information
		if dummyCount == 0 {
			fmt.Printf("=== Testing with %d packaged rules ===\n", len(packagedRules))
		} else {
			fmt.Printf("=== Testing with %d packaged + %d dummy rules (%d total) ===\n",
				len(packagedRules), dummyCount, len(ruleSet))
		}

		// Test with selected engine(s)
		if *engine == "go" || *engine == "all" {
			goResult := benchmarkEngine("go", ruleSet, benchmarkDir)
			allResults = append(allResults, goResult)
			printResult(goResult)
		}

		if *engine == "hyperscan" || *engine == "all" {
			if poltergeist.IsHyperscanAvailable() {
				hyperscanResult := benchmarkEngine("hyperscan", ruleSet, benchmarkDir)
				allResults = append(allResults, hyperscanResult)
				printResult(hyperscanResult)
			} else {
				if *engine == "hyperscan" {
					log.Fatalf("Hyperscan engine requested but not available")
				}
				fmt.Println("Hyperscan engine not available, skipping...")
			}
		}

		fmt.Println()
	}

	// Print summary table
	printSummaryTable(allResults)
}

// generateDummyRules creates dummy rules with the specified pattern
func generateDummyRules(count int) []poltergeist.Rule {
	rules := make([]poltergeist.Rule, count)

	for i := 0; i < count; i++ {
		ruleNum := fmt.Sprintf("%04d", i+1)
		rules[i] = poltergeist.Rule{
			Name: fmt.Sprintf("Dummy Rule %s", ruleNum),
			ID:   fmt.Sprintf("dummy.%s", ruleNum),
			Tags: []string{"dummy", "benchmark"},
			Pattern: fmt.Sprintf(`(?x)
        \b
          (?i)DUMMY%s\w*
          [\W]{0,40}?
          ((?i)[A-Z0-9+/-]{86,88}={0,2})
        \b`, ruleNum),
			Redact:  []int{4, 4},
			Entropy: 5.0,
			Tests: poltergeist.Test{
				Assert:    []string{fmt.Sprintf("DUMMY%s_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/==", ruleNum)},
				AssertNot: []string{"not a match"},
			},
			History: []string{"Generated for benchmark testing"},
		}
	}

	return rules
}

// benchmarkEngine tests a single engine with the given rule set
func benchmarkEngine(engineType string, rules []poltergeist.Rule, benchmarkDir string) BenchmarkResult {
	result := BenchmarkResult{
		Engine:    engineType,
		RuleCount: len(rules),
	}

	// Create engine
	var engine poltergeist.PatternEngine
	switch engineType {
	case "go":
		engine = poltergeist.NewGoRegexEngine()
	case "hyperscan":
		engine = poltergeist.NewHyperscanEngine()
	default:
		log.Fatalf("Unknown engine type: %s", engineType)
	}
	defer engine.Close()

	// Measure compilation time
	compileStart := time.Now()
	err := engine.CompileRules(rules)
	if err != nil {
		log.Fatalf("Failed to compile rules for %s engine: %v", engineType, err)
	}
	result.CompileDuration = time.Since(compileStart)

	// Create scanner
	scanner := poltergeist.NewScanner(engine)

	// Measure scan time
	scanStart := time.Now()
	_, err = scanner.ScanDirectory(benchmarkDir)
	if err != nil {
		log.Fatalf("Failed to scan directory with %s engine: %v", engineType, err)
	}
	result.ScanDuration = time.Since(scanStart)

	// Copy metrics
	result.FilesScanned = scanner.Metrics.FilesScanned
	result.FilesSkipped = scanner.Metrics.FilesSkipped
	result.TotalBytes = scanner.Metrics.TotalBytes
	result.MatchesFound = scanner.Metrics.MatchesFound

	// Calculate throughput (MB/s)
	if result.ScanDuration.Seconds() > 0 {
		result.ThroughputMBPS = float64(result.TotalBytes) / (1024 * 1024) / result.ScanDuration.Seconds()
	}

	return result
}

// printResult prints the results of a single benchmark run
func printResult(result BenchmarkResult) {
	fmt.Printf("Engine: %s\n", result.Engine)
	fmt.Printf("  Rules: %d\n", result.RuleCount)
	fmt.Printf("  Compilation Time: %v\n", result.CompileDuration)
	fmt.Printf("  Scan Time: %v\n", result.ScanDuration)
	fmt.Printf("  Files Scanned: %d\n", result.FilesScanned)
	fmt.Printf("  Files Skipped: %d\n", result.FilesSkipped)
	fmt.Printf("  Total Bytes: %s\n", poltergeist.FormatBytes(result.TotalBytes))
	fmt.Printf("  Matches Found: %d\n", result.MatchesFound)
	fmt.Printf("  Throughput: %.2f MB/s\n", result.ThroughputMBPS)
	fmt.Println()
}

// printSummaryTable prints a comparison table of all results
func printSummaryTable(results []BenchmarkResult) {
	fmt.Println("=== BENCHMARK SUMMARY ===")
	fmt.Println()

	// Header
	fmt.Printf("%-12s %-6s %-12s %-12s %-12s %-8s %-12s\n",
		"Engine", "Rules", "Compile(ms)", "Scan(ms)", "Total(ms)", "Matches", "Throughput")
	fmt.Printf("%-12s %-6s %-12s %-12s %-12s %-8s %-12s\n",
		"--------", "-----", "-----------", "--------", "---------", "-------", "----------")

	// Data rows
	for _, result := range results {
		totalTime := result.CompileDuration + result.ScanDuration
		fmt.Printf("%-12s %-6d %-12.1f %-12.1f %-12.1f %-8d %-12.2f\n",
			result.Engine,
			result.RuleCount,
			float64(result.CompileDuration.Nanoseconds())/1e6,
			float64(result.ScanDuration.Nanoseconds())/1e6,
			float64(totalTime.Nanoseconds())/1e6,
			result.MatchesFound,
			result.ThroughputMBPS,
		)
	}

	fmt.Println()

	// Performance comparison
	fmt.Println("=== PERFORMANCE ANALYSIS ===")

	// Group results by rule count
	ruleGroups := make(map[int][]BenchmarkResult)
	for _, result := range results {
		ruleGroups[result.RuleCount] = append(ruleGroups[result.RuleCount], result)
	}

	fmt.Printf("%-6s %-15s %-15s %-15s\n", "Rules", "Go Total(ms)", "HS Total(ms)", "Speedup")
	fmt.Printf("%-6s %-15s %-15s %-15s\n", "-----", "------------", "------------", "-------")

	// Get all rule counts from results and sort them
	ruleCounts := make([]int, 0)
	for ruleCount := range ruleGroups {
		ruleCounts = append(ruleCounts, ruleCount)
	}

	// Simple sort
	for i := 0; i < len(ruleCounts); i++ {
		for j := i + 1; j < len(ruleCounts); j++ {
			if ruleCounts[i] > ruleCounts[j] {
				ruleCounts[i], ruleCounts[j] = ruleCounts[j], ruleCounts[i]
			}
		}
	}

	for _, rules := range ruleCounts {
		group := ruleGroups[rules]

		var goTime, hsTime time.Duration
		var hasGo, hasHS bool

		for _, result := range group {
			totalTime := result.CompileDuration + result.ScanDuration
			if result.Engine == "go" {
				goTime = totalTime
				hasGo = true
			} else if result.Engine == "hyperscan" {
				hsTime = totalTime
				hasHS = true
			}
		}

		speedup := "N/A"
		if hasGo && hasHS && hsTime > 0 {
			speedup = fmt.Sprintf("%.2fx", float64(goTime.Nanoseconds())/float64(hsTime.Nanoseconds()))
		}

		goTimeStr := "N/A"
		if hasGo {
			goTimeStr = fmt.Sprintf("%.1f", float64(goTime.Nanoseconds())/1e6)
		}

		hsTimeStr := "N/A"
		if hasHS {
			hsTimeStr = fmt.Sprintf("%.1f", float64(hsTime.Nanoseconds())/1e6)
		}

		// Adjust rules display for packaged rules
		rulesDisplay := fmt.Sprintf("%d", rules)
		if rules == 0 && len(results) > 0 {
			rulesDisplay = fmt.Sprintf("%d*", results[0].RuleCount) // First result should be packaged rules
		}

		fmt.Printf("%-6s %-15s %-15s %-15s\n", rulesDisplay, goTimeStr, hsTimeStr, speedup)
	}

	fmt.Println()
	fmt.Println("* = packaged rules only")
	fmt.Println("HS = Hyperscan/Vectorscan")
}
