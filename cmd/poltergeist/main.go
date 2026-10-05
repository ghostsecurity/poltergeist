package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	poltergeist "github.com/ghostsecurity/poltergeist/v2/pkg"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
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
	fmt.Fprintf(os.Stderr, "  -format string\n")
	fmt.Fprintf(os.Stderr, "        Output format: 'text' (default), 'json', or 'md'\n")
	fmt.Fprintf(os.Stderr, "  -output string\n")
	fmt.Fprintf(os.Stderr, "        Write output to file (auto-detects format from .json or .md extension)\n")
	fmt.Fprintf(os.Stderr, "  -no-color\n")
	fmt.Fprintf(os.Stderr, "        Disable colored output (text format only)\n")
	fmt.Fprintf(os.Stderr, "  -classify\n        Send raw candidates, bounded code, and relative paths to TypeSafe; requires TYPESAFE_API_KEY\n")
	fmt.Fprintf(os.Stderr, "  -classify-all\n        Include hidden low-entropy candidates (requires -classify)\n")
	fmt.Fprintf(os.Stderr, "  -classify-timeout duration\n        Enrichment budget (default 10s)\n")
	fmt.Fprintf(os.Stderr, "  -classify-max-candidates int\n        Candidate cap (default 1000)\n")
	fmt.Fprintf(os.Stderr, "  -classify-cache-dir string\n        Opt-in private cache; entries expire after 24 hours\n")
	fmt.Fprintf(os.Stderr, "  -help\n")
	fmt.Fprintf(os.Stderr, "        Show this help message\n")
	fmt.Fprintf(os.Stderr, "  -version\n")
	fmt.Fprintf(os.Stderr, "        Show version information\n")
	fmt.Fprintf(os.Stderr, "\nIf no rules are specified via -rules flag or command-line patterns,\n")
	fmt.Fprintf(os.Stderr, "the tool will use built-in detection rules for common secrets.\n")
	fmt.Fprintf(os.Stderr, "\nBy default, only matches that meet minimum entropy requirements are shown.\n")
	fmt.Fprintf(os.Stderr, "Use -low-entropy to see all matches including low-entropy false positives.\n")
}

// Version information (set by build)
var version = "dev"

// Command-line flags
var (
	classifyFlag        = flag.Bool("classify", false, "Send raw candidates, bounded code, and relative paths to TypeSafe for advisory classification")
	classifyAllFlag     = flag.Bool("classify-all", false, "Classify all candidates, including hidden low-entropy matches (requires -classify)")
	classifyTimeoutFlag = flag.Duration("classify-timeout", 10*time.Second, "Total enrichment budget")
	classifyMaxFlag     = flag.Int("classify-max-candidates", 1000, "Maximum classification candidates")
	classifyCacheFlag   = flag.String("classify-cache-dir", "", "Opt-in private classification cache directory (24 hour expiry)")
	engineFlag          = flag.String("engine", "auto", "Pattern engine to use: 'auto', 'go' for Go regex, 'hyperscan' for Hyperscan/Vectorscan")
	rulesFlag           = flag.String("rules", "", "YAML file or directory containing pattern rules")
	dnrFlag             = flag.Bool("dnr", false, "Do not redact - show full matches instead of redacted versions")
	lowEntropyFlag      = flag.Bool("low-entropy", false, "Show matches that don't meet minimum entropy requirements")
	formatFlag          = flag.String("format", "text", "Output format: text, json, md")
	outputFlag          = flag.String("output", "", "Write output to file (auto-detects format from extension)")
	noColorFlag         = flag.Bool("no-color", false, "Disable colored output (text format only)")
	helpFlag            = flag.Bool("help", false, "Show help message")
	versionFlag         = flag.Bool("version", false, "Show version information")
)

func main() {
	flag.Parse()

	if *helpFlag {
		printUsage()
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Printf("poltergeist %s\n", version)
		os.Exit(0)
	}

	var classification *poltergeist.ClassificationOptions
	if *classifyFlag {
		if *classifyTimeoutFlag <= 0 || *classifyMaxFlag <= 0 {
			fmt.Fprintln(os.Stderr, "Classification limits must be positive")
			os.Exit(1)
		}
		classifier, err := poltergeist.NewJevClassifier(poltergeist.JevOptions{APIKey: os.Getenv("TYPESAFE_API_KEY"), CacheDir: *classifyCacheFlag})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		classification = &poltergeist.ClassificationOptions{Classifier: classifier, Timeout: *classifyTimeoutFlag, MaxCandidates: *classifyMaxFlag, AllCandidates: *classifyAllFlag, IncludeLowEntropy: *lowEntropyFlag}
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
		fmt.Fprintf(os.Stderr, "Using built-in rules (%d patterns loaded)\n", len(defaultRules))
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
	defer func() { _ = engine.Close() }()

	// Create scanner with optimized settings
	scanner := poltergeist.NewScannerWithOptions(engine, runtime.NumCPU()*2, 100*1024*1024)
	scanner.DisableRedaction = *dnrFlag
	scanner.Classification = classification

	fmt.Fprintf(os.Stderr, "Starting secret scan with %d workers using %s engine...\n", scanner.WorkerCount, engine.Name())
	fmt.Fprintf(os.Stderr, "Scanning: %s\n", scanPath)
	fmt.Fprintf(os.Stderr, "Rules loaded: %d patterns\n", len(rules))
	for _, rule := range rules {
		fmt.Fprintf(os.Stderr, "  - %s (ID: %s)\n", rule.Name, rule.ID)
	}

	fmt.Fprintln(os.Stderr)

	start := time.Now()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results, err := scanner.ScanDirectoryContext(ctx, scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}
	duration := time.Since(start)

	// Filter results based on entropy if flag is not set
	var filteredResults []poltergeist.ScanResult
	var lowEntropyCount int

	for _, result := range results {
		if result.RuleEntropyThresholdMet || *lowEntropyFlag {
			filteredResults = append(filteredResults, result)
		} else {
			lowEntropyCount++
		}
	}

	// Gather metrics
	filesScanned := atomic.LoadInt64(&scanner.Metrics.FilesScanned)
	filesSkipped := atomic.LoadInt64(&scanner.Metrics.FilesSkipped)
	totalBytes := atomic.LoadInt64(&scanner.Metrics.TotalBytes)
	matchesFound := atomic.LoadInt64(&scanner.Metrics.MatchesFound)

	// Determine output format (auto-detect from file extension if output flag is set)
	outputFormat := *formatFlag
	if *outputFlag != "" {
		if strings.HasSuffix(*outputFlag, ".md") && *formatFlag == "text" {
			outputFormat = "md"
		} else if strings.HasSuffix(*outputFlag, ".json") && *formatFlag == "text" {
			outputFormat = "json"
		}
	}

	// Determine if we should use colors
	useColor := !*noColorFlag && isTerminal() && *outputFlag == "" && outputFormat == "text"

	// Format output
	var output string
	var exitCode int

	switch outputFormat {
	case "json":
		output, exitCode = formatJSON(filteredResults, filesScanned, filesSkipped, totalBytes, matchesFound, lowEntropyCount, scanner.Metrics.Classification)
	case "md", "markdown":
		output, exitCode = formatMarkdown(filteredResults, scanPath, filesScanned, filesSkipped, totalBytes, matchesFound, lowEntropyCount, duration)
	case "text":
		output, exitCode = formatText(filteredResults, filesScanned, filesSkipped, totalBytes, matchesFound, lowEntropyCount, duration, useColor, *dnrFlag)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown format %q (use text, json, or md)\n", outputFormat)
		os.Exit(1)
	}

	if scanner.Metrics.Classification != nil && outputFormat != "json" {
		m := scanner.Metrics.Classification
		summary := fmt.Sprintf("Classification: %d eligible, %d scored (%d uncertain), %d skipped, %d failed; %d cache hits; %d requests, %d retries; %d input tokens, %d output tokens; %s enrichment\n", m.Eligible, m.Scored, m.Uncertain, m.Skipped, m.Failed, m.CacheHits, m.Requests, m.Retries, m.InputTokens, m.OutputTokens, m.Duration)
		output += summary
	}
	// Write to file or stdout
	if *outputFlag != "" {
		if err := os.WriteFile(*outputFlag, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *outputFlag)
	} else {
		fmt.Print(output)
	}

	os.Exit(exitCode)
}

// formatText formats results as colored text output
func formatText(results []poltergeist.ScanResult, filesScanned, filesSkipped, totalBytes, matchesFound int64, lowEntropyCount int, duration time.Duration, useColor bool, showFullMatch bool) (string, int) {
	var sb strings.Builder

	fmt.Fprintf(&sb, "\n%s\n", divider(50))
	fmt.Fprintf(&sb, "%s SCAN SUMMARY %s\n", bold("", useColor), "")
	fmt.Fprintf(&sb, "%s\n\n", divider(50))

	fmt.Fprintf(&sb, "Files scanned:  %s\n", bold(fmt.Sprintf("%d", filesScanned), useColor))
	fmt.Fprintf(&sb, "Total content:  %s\n", poltergeist.FormatBytes(totalBytes))

	if len(results) == 0 {
		fmt.Fprintf(&sb, "Secrets found:  %s\n\n", green("0", useColor))
		if lowEntropyCount > 0 {
			fmt.Fprintf(&sb, "%s No high-entropy secrets found. %d low-entropy matches were filtered out.\n", green("✓", useColor), lowEntropyCount)
			sb.WriteString("  Use -low-entropy to see all matches.\n\n")
		} else {
			fmt.Fprintf(&sb, "%s No secrets found!\n\n", green("✓", useColor))
		}
		return sb.String(), 0
	}

	fmt.Fprintf(&sb, "Secrets found:  %s", red(fmt.Sprintf("%d", len(results)), useColor))
	if lowEntropyCount > 0 {
		fmt.Fprintf(&sb, " (%d low-entropy filtered)", lowEntropyCount)
	}
	sb.WriteString("\n\n")

	// Group results by file
	fileResults := make(map[string][]poltergeist.ScanResult)
	for _, result := range results {
		fileResults[result.FilePath] = append(fileResults[result.FilePath], result)
	}

	for filePath, fileMatches := range fileResults {
		fmt.Fprintf(&sb, "%s %s %s (%d matches)\n",
			red("●", useColor),
			bold(filePath, useColor),
			"",
			len(fileMatches))

		for _, match := range fileMatches {
			fmt.Fprintf(&sb, "  %s Line %s: %s\n",
				yellow("└─", useColor),
				cyan(fmt.Sprintf("%d", match.LineNumber), useColor),
				match.RuleName)

			displayMatch := match.Redacted
			if showFullMatch {
				displayMatch = match.Match
			}

			// Truncate very long matches
			if len(displayMatch) > 80 {
				displayMatch = displayMatch[:77] + "..."
			}

			fmt.Fprintf(&sb, "     %s\n", displayMatch)

			if match.RuleID != "" {
				fmt.Fprintf(&sb, "     ID: %s\n", match.RuleID)
			}

			// Display entropy information
			metStr := "No"
			if match.RuleEntropyThresholdMet {
				metStr = "Yes"
			}
			sb.WriteString(classificationText(match.Classification))
			fmt.Fprintf(&sb, "     Entropy: %.2f | Threshold: %.2f | Met: %s\n",
				match.Entropy, match.RuleEntropyThreshold, metStr)
		}
		sb.WriteString("\n")
	}

	// Metrics footer
	fmt.Fprintf(&sb, "%s\n", divider(50))
	fmt.Fprintf(&sb, "Files skipped: %d (binary/large files)\n", filesSkipped)
	fmt.Fprintf(&sb, "Scan completed in %v\n\n", duration)

	fmt.Fprintf(&sb, "%s Review and address the secrets above.\n\n", yellow("!", useColor))
	return sb.String(), 1
}

// formatJSON formats results as JSON
func formatJSON(results []poltergeist.ScanResult, filesScanned, filesSkipped, totalBytes, matchesFound int64, lowEntropyCount int, classification ...*poltergeist.ClassificationMetrics) (string, int) {
	output := struct {
		Summary struct {
			FilesScanned int64 `json:"files_scanned"`
			FilesSkipped int64 `json:"files_skipped"`
			TotalBytes   int64 `json:"total_bytes"`
			MatchesFound int64 `json:"matches_found"`
			HighEntropy  int   `json:"high_entropy_matches"`
			LowEntropy   int   `json:"low_entropy_matches"`
		} `json:"summary"`
		Classification *poltergeist.ClassificationMetrics `json:"classification,omitempty"`
		Results        []poltergeist.ScanResult           `json:"results"`
	}{
		Results: results,
	}

	if len(classification) > 0 {
		output.Classification = classification[0]
	}
	output.Summary.FilesScanned = filesScanned
	output.Summary.FilesSkipped = filesSkipped
	output.Summary.TotalBytes = totalBytes
	output.Summary.MatchesFound = matchesFound
	output.Summary.HighEntropy = len(results)
	output.Summary.LowEntropy = lowEntropyCount

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error encoding JSON: %v\n", err), 1
	}

	exitCode := 0
	if len(results) > 0 {
		exitCode = 1
	}
	return string(data) + "\n", exitCode
}

// formatMarkdown formats results as markdown
func formatMarkdown(results []poltergeist.ScanResult, scanPath string, filesScanned, filesSkipped, totalBytes, matchesFound int64, lowEntropyCount int, duration time.Duration) (string, int) {
	var sb strings.Builder

	sb.WriteString("# Secret Scan Report\n\n")
	fmt.Fprintf(&sb, "**Scanned:** `%s`  \n", scanPath)
	fmt.Fprintf(&sb, "**Date:** %s  \n\n", time.Now().Format("2006-01-02 15:04:05"))

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(&sb, "| Files scanned | %d |\n", filesScanned)
	fmt.Fprintf(&sb, "| Files skipped | %d |\n", filesSkipped)
	fmt.Fprintf(&sb, "| Total content | %s |\n", poltergeist.FormatBytes(totalBytes))
	fmt.Fprintf(&sb, "| Secrets found | %d |\n", len(results))
	if lowEntropyCount > 0 {
		fmt.Fprintf(&sb, "| Low-entropy filtered | %d |\n", lowEntropyCount)
	}
	fmt.Fprintf(&sb, "| Scan duration | %v |\n\n", duration)

	if len(results) == 0 {
		sb.WriteString("✅ **No secrets found!**\n")
		if lowEntropyCount > 0 {
			fmt.Fprintf(&sb, "\n*Note: %d low-entropy matches were filtered out.*\n", lowEntropyCount)
		}
		return sb.String(), 0
	}

	sb.WriteString("## Findings\n\n")

	// Group results by file
	fileResults := make(map[string][]poltergeist.ScanResult)
	for _, result := range results {
		fileResults[result.FilePath] = append(fileResults[result.FilePath], result)
	}

	for filePath, fileMatches := range fileResults {
		fmt.Fprintf(&sb, "### `%s`\n\n", filePath)
		fmt.Fprintf(&sb, "**Matches:** %d\n\n", len(fileMatches))

		for i, match := range fileMatches {
			fmt.Fprintf(&sb, "#### Finding %d\n\n", i+1)
			fmt.Fprintf(&sb, "- **Line:** %d\n", match.LineNumber)
			fmt.Fprintf(&sb, "- **Rule:** %s\n", match.RuleName)
			if match.RuleID != "" {
				fmt.Fprintf(&sb, "- **Rule ID:** %s\n", match.RuleID)
			}
			fmt.Fprintf(&sb, "- **Match:** `%s`\n", match.Redacted)
			if match.Classification != nil {
				sb.WriteString("- " + classificationText(match.Classification))
			}
			fmt.Fprintf(&sb, "- **Entropy:** %.2f\n", match.Entropy)
			fmt.Fprintf(&sb, "- **Threshold:** %.2f\n", match.RuleEntropyThreshold)
			metStr := "No"
			if match.RuleEntropyThresholdMet {
				metStr = "Yes"
			}
			fmt.Fprintf(&sb, "- **Threshold Met:** %s\n", metStr)
			sb.WriteString("\n")
		}
	}

	return sb.String(), 1
}

// Helper functions

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func divider(n int) string {
	return strings.Repeat("─", n)
}

func red(s string, useColor bool) string {
	if useColor {
		return colorRed + s + colorReset
	}
	return s
}

func green(s string, useColor bool) string {
	if useColor {
		return colorGreen + s + colorReset
	}
	return s
}

func yellow(s string, useColor bool) string {
	if useColor {
		return colorYellow + s + colorReset
	}
	return s
}

func cyan(s string, useColor bool) string {
	if useColor {
		return colorCyan + s + colorReset
	}
	return s
}

func bold(s string, useColor bool) string {
	if useColor {
		return colorBold + s + colorReset
	}
	return s
}

func classificationText(c *poltergeist.ClassificationResult) string {
	if c == nil {
		return ""
	}
	if c.RealSecretProbability != nil {
		return fmt.Sprintf("Classification: %s | Real-secret likelihood: %.1f%% | Model: %s | Policy: %s | Source: %s\n", c.Label, *c.RealSecretProbability*100, c.Model, c.PolicyVersion, c.Source)
	}
	return fmt.Sprintf("Classification: %s (%s)\n", c.Status, c.Reason)
}
