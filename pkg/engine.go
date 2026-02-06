package poltergeist

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/flier/gohs/hyperscan"
)

// PatternEngine interface for different regex engines
type PatternEngine interface {
	// CompileRules compiles multiple rules for use with this engine
	CompileRules(rules []Rule) error

	// FindAllInLine finds all matches in a single line of text
	FindAllInLine(line string) []MatchResult

	// FindAllInContent finds all matches in content with position information
	FindAllInContent(content []byte) []MatchResult

	// Close releases any resources (for engines like hyperscan)
	Close() error

	// Name returns the engine name for display purposes
	Name() string
}

// HyperscanEngine implements PatternEngine using Hyperscan/Vectorscan
type HyperscanEngine struct {
	database        hyperscan.BlockDatabase
	scratchPool     sync.Pool
	rules           []RuntimeRule
	goRegexPatterns []*regexp.Regexp // Pre-compiled Go regex for quickMatch refinement
}

// NewHyperscanEngine creates a new Hyperscan engine
func NewHyperscanEngine() PatternEngine {
	return &HyperscanEngine{}
}

// CompileRules compiles multiple rules for Hyperscan
func (e *HyperscanEngine) CompileRules(rules []Rule) error {
	e.rules = make([]RuntimeRule, len(rules))
	for i, rule := range rules {
		e.rules[i] = rule.ToRuntimeRule()
	}

	// Pre-compile Go regex patterns for quickMatch refinement
	e.goRegexPatterns = make([]*regexp.Regexp, len(rules))
	for i, rule := range rules {
		compiled, err := regexp.Compile(NormalizeExtendedRegex(rule.Pattern))
		if err != nil {
			e.goRegexPatterns[i] = nil // Graceful fallback - Hyperscan may still work
			continue
		}
		e.goRegexPatterns[i] = compiled
	}

	// Create hyperscan patterns for all rules
	patterns := make([]*hyperscan.Pattern, len(rules))
	for i, rule := range rules {
		// Pattern compilation flags:
		//
		// `Caseless`
		// This flag sets the expression to be matched case-insensitively by default. The
		// expression may still use PCRE tokens (notably (?i) and (?-i)) to switch case-insensitive
		// matching on and off.
		//
		// Currently not enabled. We set case-insensitive matching on and off with PCRE tokens.
		//
		//
		// `DotAll`
		// This flag sets any instances of the . token to match newline characters as well as
		// all other characters. The PCRE specification states that the . token does not match
		// newline characters by default, so without this flag the . token will not cross line
		// boundaries.
		//
		// Currently enabled. However, we do not currently care about newlines, as we are
		// processing lines at a time. This doesn't have any effect not, but we will likely want
		// it enabled if/when we start processing raw content.
		//
		//
		// `SomLeftMost`
		// This flag instructs Hyperscan to report the leftmost possible start of match offset
		// when a match is reported for this expression. (By default, no start of match is
		// returned.)
		//
		// Currently not enabled. Cannot be used with `SingleMatch`.
		//
		//
		// `SingleMatch`
		// This flag sets the expression’s match ID to match at most once. In streaming mode, this
		// means that the expression will return only a single match over the lifetime of the stream,
		// rather than reporting every match as per standard Hyperscan semantics. In block mode or
		// vectored mode, only the first match for each invocation of hs_scan() or hs_scan_vector()
		// will be returned.
		//
		// Currently enabled. Some patterns can cause multiple matches, exploding the results. For
		// now, we only want one match per pattern.
		//
		patterns[i] = hyperscan.NewPattern(rule.Pattern, hyperscan.DotAll|hyperscan.SingleMatch)
		patterns[i].Id = int(i)
	}

	// Test each pattern individually first to identify rules that fail to compile
	for i, pattern := range patterns {
		rule := rules[i]
		_, err := hyperscan.NewBlockDatabase(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile pattern for rule '%s' (pattern: %s): %w",
				rule.Name, rule.Pattern, err)
		}
	}

	// Compile all patterns into a single database
	database, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		return fmt.Errorf("failed to compile hyperscan patterns: %w", err)
	}

	e.database = database

	// Initialize scratch pool
	e.scratchPool = sync.Pool{
		New: func() any {
			scratch, err := hyperscan.NewManagedScratch(database)
			if err != nil {
				return nil
			}
			return scratch
		},
	}

	return nil
}

// FindAllInLine finds all matches in a single line using line-by-line scanning
func (e *HyperscanEngine) FindAllInLine(line string) []MatchResult {
	if e.database == nil {
		return nil
	}

	// Get scratch space from pool
	scratchInterface := e.scratchPool.Get()
	if scratchInterface == nil {
		return nil
	}
	scratch := scratchInterface.(*hyperscan.Scratch)
	defer e.scratchPool.Put(scratch)

	var results []MatchResult

	// Scan the line
	err := e.database.Scan([]byte(line), scratch, func(id uint, from, to uint64, flags uint, data any) error {
		match := line[from:to]

		// Use the pattern ID to identify which rule matched
		rule := e.rules[id]

		// We don't get the beginning of the match (SOM) from Hyperscan when using
		// `SingleMatch`, which is mutually exclusive with `SomLeftMost`. So we use our
		// own quick match to refine the line match down to an exact `from` and `to`.
		matches := quickMatchWithRegex(line, e.goRegexPatterns[id])
		if len(matches) > 0 {
			from = matches[0]
			to = matches[1]

			// Discard the ambitious match from Hyperscan
			match = line[from:to]
		}

		// Always redact the match - never show raw secrets
		var redacted string
		if len(rule.Redact) > 0 &&
			rule.Redact[0] > 0 &&
			rule.Redact[1] > 0 &&
			len(match) > rule.Redact[0]+rule.Redact[1] {
			// Use rule-specific redaction offsets
			redacted = match[:rule.Redact[0]] + strings.Repeat("*", min(5, len(match))) + match[len(match)-rule.Redact[1]:]
		} else if len(match) > 8 {
			// Fallback: show first 4 and last 4 chars
			redacted = match[:4] + strings.Repeat("*", min(5, len(match)-8)) + match[len(match)-4:]
		} else {
			// Very short match: fully redact
			redacted = strings.Repeat("*", len(match))
		}

		// Calculate entropy and check if it meets the minimum requirement
		entropy := ShannonEntropy(match)
		entropyMet := entropy >= rule.Entropy

		results = append(results, MatchResult{
			Start:                   int(from),
			End:                     int(to),
			Match:                   match,
			Redacted:                redacted,
			RuleName:                rule.Name,
			RuleID:                  rule.ID,
			Entropy:                 entropy,
			RuleEntropyThreshold:    rule.Entropy,
			RuleEntropyThresholdMet: entropyMet,
		})

		return nil
	}, nil)
	if err != nil {
		return nil
	}

	return results
}

// FindAllInContent finds all matches in content with positions
func (e *HyperscanEngine) FindAllInContent(content []byte) []MatchResult {
	if e.database == nil {
		return nil
	}

	// Get scratch space from pool
	scratchInterface := e.scratchPool.Get()
	if scratchInterface == nil {
		return nil
	}
	scratch := scratchInterface.(*hyperscan.Scratch)
	defer e.scratchPool.Put(scratch)

	var results []MatchResult

	// Scan the content
	err := e.database.Scan(content, scratch, func(id uint, from, to uint64, flags uint, data any) error {
		match := string(content[from:to])

		// Use the pattern ID to identify which rule matched
		rule := e.rules[id]

		// Always redact the match - never show raw secrets
		var redacted string
		if len(rule.Redact) > 0 &&
			rule.Redact[0] > 0 &&
			rule.Redact[1] > 0 &&
			len(match) > rule.Redact[0]+rule.Redact[1] {
			// Use rule-specific redaction offsets
			redacted = match[:rule.Redact[0]] + strings.Repeat("*", min(5, len(match))) + match[len(match)-rule.Redact[1]:]
		} else if len(match) > 8 {
			// Fallback: show first 4 and last 4 chars
			redacted = match[:4] + strings.Repeat("*", min(5, len(match)-8)) + match[len(match)-4:]
		} else {
			// Very short match: fully redact
			redacted = strings.Repeat("*", len(match))
		}

		// Calculate entropy and check if it meets the minimum requirement
		entropy := ShannonEntropy(match)
		entropyMet := entropy >= rule.Entropy

		results = append(results, MatchResult{
			Start:                   int(from),
			End:                     int(to),
			Match:                   match,
			Redacted:                redacted,
			RuleName:                rule.Name,
			RuleID:                  rule.ID,
			Entropy:                 entropy,
			RuleEntropyThreshold:    rule.Entropy,
			RuleEntropyThresholdMet: entropyMet,
		})

		return nil
	}, nil)
	if err != nil {
		return nil
	}

	return results
}

// Close releases resources
func (e *HyperscanEngine) Close() error {
	if e.database != nil {
		return e.database.Close()
	}
	return nil
}

// Name returns the engine name
func (e *HyperscanEngine) Name() string {
	return "Hyperscan/Vectorscan"
}

// GoRegexEngine implements PatternEngine using Go's built-in regex
type GoRegexEngine struct {
	rules    []RuntimeRule
	patterns []*regexp.Regexp
}

// NewGoRegexEngine creates a new Go regex engine
func NewGoRegexEngine() *GoRegexEngine {
	return &GoRegexEngine{}
}

// CompileRules compiles multiple rules for Go regex
func (e *GoRegexEngine) CompileRules(rules []Rule) error {
	// Convert to RuntimeRules for memory efficiency
	e.rules = make([]RuntimeRule, len(rules))
	for i, rule := range rules {
		e.rules[i] = rule.ToRuntimeRule()
	}
	e.patterns = make([]*regexp.Regexp, len(rules))

	for i, rule := range rules {
		pattern := NormalizeExtendedRegex(rule.Pattern)
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile rule '%s': %w", rule.Name, err)
		}
		e.patterns[i] = compiled
	}

	return nil
}

// FindAllInLine finds all matches in a single line
func (e *GoRegexEngine) FindAllInLine(line string) []MatchResult {
	var results []MatchResult

	for i, pattern := range e.patterns {
		matches := pattern.FindAllString(line, -1)

		for _, match := range matches {
			// Always redact the match - never show raw secrets
			var redacted string
			if len(e.rules[i].Redact) > 0 &&
				e.rules[i].Redact[0] > 0 &&
				e.rules[i].Redact[1] > 0 &&
				len(match) > e.rules[i].Redact[0]+e.rules[i].Redact[1] {
				// Use rule-specific redaction offsets
				redacted = match[:e.rules[i].Redact[0]] + strings.Repeat("*", min(5, len(match))) + match[len(match)-e.rules[i].Redact[1]:]
			} else if len(match) > 8 {
				// Fallback: show first 4 and last 4 chars
				redacted = match[:4] + strings.Repeat("*", min(5, len(match)-8)) + match[len(match)-4:]
			} else {
				// Very short match: fully redact
				redacted = strings.Repeat("*", len(match))
			}

			// Calculate entropy and check if it meets the minimum requirement
			entropy := ShannonEntropy(match)
			entropyMet := entropy >= e.rules[i].Entropy

			results = append(results, MatchResult{
				Start:                   0,
				End:                     0,
				Match:                   match,
				Redacted:                redacted,
				RuleName:                e.rules[i].Name,
				RuleID:                  e.rules[i].ID,
				Entropy:                 entropy,
				RuleEntropyThreshold:    e.rules[i].Entropy,
				RuleEntropyThresholdMet: entropyMet,
			})
		}
	}

	return results
}

// FindAllInContent finds all matches in content with positions
func (e *GoRegexEngine) FindAllInContent(content []byte) []MatchResult {
	var results []MatchResult

	for i, pattern := range e.patterns {
		matches := pattern.FindAllIndex(content, -1)
		for _, match := range matches {
			matchText := string(content[match[0]:match[1]])

			// Always redact the match - never show raw secrets
			var redacted string
			if len(e.rules[i].Redact) > 0 &&
				e.rules[i].Redact[0] > 0 &&
				e.rules[i].Redact[1] > 0 &&
				len(matchText) > e.rules[i].Redact[0]+e.rules[i].Redact[1] {
				// Use rule-specific redaction offsets
				redacted = matchText[:e.rules[i].Redact[0]] + strings.Repeat("*", min(5, len(matchText))) + matchText[len(matchText)-e.rules[i].Redact[1]:]
			} else if len(matchText) > 8 {
				// Fallback: show first 4 and last 4 chars
				redacted = matchText[:4] + strings.Repeat("*", min(5, len(matchText)-8)) + matchText[len(matchText)-4:]
			} else {
				// Very short match: fully redact
				redacted = strings.Repeat("*", len(matchText))
			}

			// Calculate entropy and check if it meets the minimum requirement
			entropy := ShannonEntropy(matchText)
			entropyMet := entropy >= e.rules[i].Entropy

			results = append(results, MatchResult{
				Start:                   match[0],
				End:                     match[1],
				Match:                   matchText,
				Redacted:                redacted,
				RuleName:                e.rules[i].Name,
				RuleID:                  e.rules[i].ID,
				Entropy:                 entropy,
				RuleEntropyThreshold:    e.rules[i].Entropy,
				RuleEntropyThresholdMet: entropyMet,
			})
		}
	}

	return results
}

// Close releases resources (no-op for Go regex)
func (e *GoRegexEngine) Close() error {
	return nil
}

// Name returns the engine name
func (e *GoRegexEngine) Name() string {
	return "Go Regex"
}

// quickMatchWithRegex refines a match with the exact location using a pre-compiled regex.
// If there are multiple capture groups, we return the index of the last one.
// Returns nil if refinement fails, so the original Hyperscan match is preserved.
func quickMatchWithRegex(line string, re *regexp.Regexp) []uint64 {
	// If regex is nil (compilation failed), return nil to keep original match
	if re == nil {
		return nil
	}

	// Get the capture groups
	cg := re.FindStringSubmatch(line)

	// No match found, return nil to keep original match
	if len(cg) == 0 {
		return nil
	}

	// Get the index of the last capture group
	lastMatch := cg[len(cg)-1]
	lastMatchIndex := strings.LastIndex(line, lastMatch)
	lastMatchEnd := lastMatchIndex + len(lastMatch)

	return []uint64{uint64(lastMatchIndex), uint64(lastMatchEnd)}
}
