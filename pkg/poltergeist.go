// Package poltergeist provides a high-performance secret scanning library.
//
// This package can be used as a library to scan files and directories for
// sensitive patterns like API keys, certificate private keys, credentials,
// and other secrets. It supports multiple pattern engines (Go regex and
// Hyperscan/Vectorscan) and includes entropy analysis to reduce false positives.
//
// Basic usage:
//
//	// Load rules from YAML files
//	rules, err := poltergeist.LoadRulesFromDirectory("rules/")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create and configure engine
//	engine := poltergeist.NewGoRegexEngine()
//	defer engine.Close()
//	err = engine.CompileRules(rules)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create scanner and scan directory
//	scanner := poltergeist.NewScanner(engine)
//	results, err := scanner.ScanDirectory("/path/to/scan")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Process results
//	for _, result := range results {
//		fmt.Printf("Match: %s in %s:%d\n", result.RuleName, result.FilePath, result.LineNumber)
//	}
package poltergeist

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// ScanResult represents a match found in a file
type ScanResult struct {
	FilePath   string
	LineNumber int
	Match      string // The original matched text
	Redacted   string // The redacted version of the match
	RuleName   string // Name of the rule that matched
	RuleID     string // ID of the rule that matched
	Entropy    bool   // Whether the match met the minimum entropy requirement
}

// MatchResult represents a single pattern match within content
type MatchResult struct {
	Start    int    // Start position in content
	End      int    // End position in content
	Match    string // The matched text
	Redacted string // The redacted text
	RuleName string // Name of the rule that matched
	RuleID   string // ID of the rule that matched
	Entropy  bool   // Whether the match met the minimum entropy requirement
}

// ScanMetrics tracks scanning statistics
type ScanMetrics struct {
	FilesScanned int64 // Number of files actually scanned (not skipped)
	FilesSkipped int64 // Number of files skipped (binary, too large, etc.)
	TotalBytes   int64 // Total bytes of content scanned
	MatchesFound int64 // Total number of matches found
}

// Scanner represents the secret scanner configuration
type Scanner struct {
	Engine           PatternEngine
	WorkerCount      int
	MaxFileSize      int64 // Maximum file size to scan (in bytes)
	DisableRedaction bool  // If true, show full matches instead of redacted versions
	Metrics          *ScanMetrics
}

// FileJob represents a file to be scanned
type FileJob struct {
	Path string
	Info os.FileInfo
}

// LoadRulesFromFile loads rules from a YAML file
func LoadRulesFromFile(filename string) ([]Rule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var ruleFile RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return ruleFile.Rules, nil
}

func LoadRulesFromDirectory(dirPath string) ([]Rule, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process YAML files
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		filePath := filepath.Join(dirPath, name)
		rules, err := LoadRulesFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules from %s: %w", filePath, err)
		}

		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func LoadRules(path string) ([]Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		return LoadRulesFromDirectory(path)
	} else {
		return LoadRulesFromFile(path)
	}
}

// IsHyperscanAvailable checks if hyperscan engine can be used
func IsHyperscanAvailable() bool {
	// Try to create a hyperscan engine and test compilation
	engine := NewHyperscanEngine()
	defer engine.Close()

	// Test with a simple rule
	testRule := []Rule{{Name: "test", ID: "test.1", Pattern: "test", Tags: []string{"test"}, Entropy: 1.0}}
	err := engine.CompileRules(testRule)
	return err == nil
}

// SelectEngine chooses the appropriate engine based on rules and user preference
func SelectEngine(rules []Rule, enginePreference string) string {
	switch enginePreference {
	case "go":
		return "go"
	case "hyperscan":
		return "hyperscan"
	case "auto":
		// Use hyperscan for multiple patterns (its strength), but only if available
		if len(rules) > 1 && IsHyperscanAvailable() {
			return "hyperscan"
		}
		return "go"
	default:
		return "go"
	}
}

// NewScanner creates a new scanner with the given engine and default settings
func NewScanner(engine PatternEngine) *Scanner {
	return &Scanner{
		Engine:      engine,
		WorkerCount: 8,                 // Reasonable default
		MaxFileSize: 100 * 1024 * 1024, // 100MB max file size
		Metrics:     &ScanMetrics{},
	}
}

// NewScannerWithOptions creates a new scanner with custom options
func NewScannerWithOptions(engine PatternEngine, workerCount int, maxFileSize int64) *Scanner {
	return &Scanner{
		Engine:      engine,
		WorkerCount: workerCount,
		MaxFileSize: maxFileSize,
		Metrics:     &ScanMetrics{},
	}
}

// FormatBytes converts bytes to human-readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ScanDirectory scans a directory for pattern matches using parallel workers
func (s *Scanner) ScanDirectory(rootPath string) ([]ScanResult, error) {
	// Channel for file jobs
	jobs := make(chan FileJob, 1000)

	// Channel for results
	results := make(chan ScanResult, 1000)

	// Channel to signal completion
	done := make(chan bool)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.WorkerCount; i++ {
		wg.Add(1)
		go s.worker(jobs, results, &wg)
	}

	// Start result collector
	var allResults []ScanResult
	go func() {
		for result := range results {
			allResults = append(allResults, result)
		}
		done <- true
	}()

	// Walk directory and send jobs
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error accessing %s: %v\n", path, err)
			return nil // Continue with other files
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip very large files
		if info.Size() > s.MaxFileSize {
			atomic.AddInt64(&s.Metrics.FilesSkipped, 1)
			return nil
		}

		// Skip empty files
		if info.Size() == 0 {
			atomic.AddInt64(&s.Metrics.FilesSkipped, 1)
			return nil
		}

		jobs <- FileJob{Path: path, Info: info}
		return nil
	})

	// Close jobs channel and wait for workers to finish
	close(jobs)
	wg.Wait()
	close(results)

	// Wait for result collection to complete
	<-done

	return allResults, err
}

// worker processes file scan jobs
func (s *Scanner) worker(jobs <-chan FileJob, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		if isBinaryFile(job.Path) {
			atomic.AddInt64(&s.Metrics.FilesSkipped, 1)
			continue
		}

		fileResults, err := s.scanFile(job.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", job.Path, err)
			atomic.AddInt64(&s.Metrics.FilesSkipped, 1)
			continue
		}

		// Successfully scanned a file
		atomic.AddInt64(&s.Metrics.FilesScanned, 1)
		atomic.AddInt64(&s.Metrics.TotalBytes, job.Info.Size())

		// Track matches found
		matchCount := int64(len(fileResults))
		atomic.AddInt64(&s.Metrics.MatchesFound, matchCount)

		for _, result := range fileResults {
			results <- result
		}
	}
}

// scanFile scans a single file for pattern matches
func (s *Scanner) scanFile(filePath string) ([]ScanResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []ScanResult
	scanner := bufio.NewScanner(file)
	lineNumber := 1

	// Use a larger buffer for better performance
	buf := make([]byte, 0, 128*1024)
	scanner.Buffer(buf, 1024*1024*10) // 10MB max line length

	for scanner.Scan() {
		line := scanner.Text()

		// Find all matches in this line
		matches := s.Engine.FindAllInLine(line)
		for _, match := range matches {
			results = append(results, ScanResult{
				FilePath:   filePath,
				LineNumber: lineNumber,
				Match:      match.Match,
				Redacted:   match.Redacted,
				RuleName:   match.RuleName,
				RuleID:     match.RuleID,
				Entropy:    match.Entropy,
			})
		}

		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// isBinaryFile attempts to determine if a file is binary
func isBinaryFile(filePath string) bool {
	// First, check file extension for known binary types
	ext := strings.ToLower(filepath.Ext(filePath))
	binaryExts := map[string]bool{
		".a":     true,
		".avi":   true,
		".bin":   true,
		".bmp":   true,
		".class": true,
		".dll":   true,
		".doc":   true,
		".docx":  true,
		".dylib": true,
		".exe":   true,
		".gif":   true,
		".gz":    true,
		".img":   true,
		".iso":   true,
		".jar":   true,
		".jpg":   true,
		".jpeg":  true,
		".lib":   true,
		".mov":   true,
		".mp3":   true,
		".mp4":   true,
		".o":     true,
		".obj":   true,
		".pdf":   true,
		".png":   true,
		".rar":   true,
		".so":    true,
		".tar":   true,
		".war":   true,
		".xls":   true,
		".xlsx":  true,
		".zip":   true,
	}

	if binaryExts[ext] {
		return true
	}

	// For unknown extensions, read the first few bytes to check for binary content
	file, err := os.Open(filePath)
	if err != nil {
		return true // Assume binary if we can't read it
	}
	defer file.Close()

	// Read first 512 bytes (standard for file type detection)
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return true // Assume binary if we can't read it
	}

	// Check for null bytes (common indicator of binary files)
	for i := range n {
		if buffer[i] == 0 {
			return true
		}
	}

	// Additional heuristic: if more than 30% of bytes are non-printable, consider it binary
	nonPrintable := 0
	for i := range n {
		b := buffer[i]
		if b < 32 && b != 9 && b != 10 && b != 13 { // Not tab, newline, or carriage return
			nonPrintable++
		}
	}

	return float64(nonPrintable)/float64(n) > 0.30
}
