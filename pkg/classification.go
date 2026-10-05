package poltergeist

import (
	"container/heap"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const ClassificationPolicyVersion = "secret-authenticity-v1"
const DefaultJevModel = "jev-1.13.0"

// ClassificationResult is advisory. Missing probabilities never mean zero.
type ClassificationResult struct {
	Status                string   `json:"status"`
	RealSecretProbability *float64 `json:"real_secret_probability,omitempty"`
	Label                 string   `json:"label,omitempty"`
	Model                 string   `json:"model,omitempty"`
	PolicyVersion         string   `json:"policy_version"`
	Source                string   `json:"source,omitempty"`
	ContextTruncated      bool     `json:"context_truncated,omitempty"`
	Reason                string   `json:"reason,omitempty"`
}

// ClassificationMetrics describe the last enrichment run. Duration excludes detection.
type ClassificationMetrics struct {
	Eligible     int64         `json:"eligible"`
	Scored       int64         `json:"scored"`
	Uncertain    int64         `json:"uncertain"`
	Skipped      int64         `json:"skipped"`
	Failed       int64         `json:"failed"`
	CacheHits    int64         `json:"cache_hits"`
	Requests     int64         `json:"requests"`
	Retries      int64         `json:"retries"`
	InputTokens  int64         `json:"input_tokens"`
	OutputTokens int64         `json:"output_tokens"`
	RereadBytes  int64         `json:"reread_bytes"`
	Duration     time.Duration `json:"duration_ns"`
}

// ClassificationOptions enables enrichment. Zero limits select the defaults.
// By default only entropy-passing candidates are eligible. IncludeLowEntropy
// mirrors report eligibility; AllCandidates explicitly overrides it.
type ClassificationOptions struct {
	Classifier        CandidateClassifier
	IncludeLowEntropy bool
	AllCandidates     bool
	Timeout           time.Duration
	MaxCandidates     int
}

func (o *ClassificationOptions) validate() error {
	if o.Classifier == nil || o.Timeout < 0 || o.MaxCandidates < 0 {
		return fmt.Errorf("invalid classification configuration")
	}
	return nil
}

// ClassificationCandidate is transient sensitive input. Never log or persist it.
// Start and End are byte offsets in the original line, not the cropped context.
type ClassificationCandidate struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Value    string `json:"value"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
}

type ClassificationLine struct {
	Number    int    `json:"number"`
	Text      string `json:"text"`
	StartByte int    `json:"start_byte"`
}

// ClassificationBatch contains one local code window and its targets.
type ClassificationBatch struct {
	Context    []ClassificationLine      `json:"context"`
	Candidates []ClassificationCandidate `json:"candidates"`
	Truncated  bool                      `json:"truncated"`
}

// ClassificationBatchResult aligns Probabilities with the submitted candidates.
type ClassificationBatchResult struct {
	Probabilities []float64
	Model         string
	Source        string
	Requests      int64
	Retries       int64
	InputTokens   int64
	OutputTokens  int64
}

// CandidateClassifier must honor cancellation and support concurrent calls.
// Returned errors should contain only safe reason codes, never source or values.
type CandidateClassifier interface {
	ClassifyBatch(context.Context, ClassificationBatch) (ClassificationBatchResult, error)
}

type candidateProvenance struct {
	start, end int
	lineHash   [32]byte
	info       os.FileInfo
}

type selectedCandidate struct {
	index            int
	path             string
	line, start, end int
	rule             string
}
type candidateHeap []selectedCandidate

func (h candidateHeap) Len() int { return len(h) }
func lessCandidate(a, b selectedCandidate) bool {
	if a.path != b.path {
		return a.path < b.path
	}
	if a.line != b.line {
		return a.line < b.line
	}
	if a.start != b.start {
		return a.start < b.start
	}
	if a.end != b.end {
		return a.end < b.end
	}
	if a.rule != b.rule {
		return a.rule < b.rule
	}
	return a.index < b.index
}
func (h candidateHeap) Less(i, j int) bool { return lessCandidate(h[j], h[i]) }
func (h candidateHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *candidateHeap) Push(x any)        { *h = append(*h, x.(selectedCandidate)) }
func (h *candidateHeap) Pop() any          { a := *h; x := a[len(a)-1]; *h = a[:len(a)-1]; return x }

type preparedBatch struct {
	batch   ClassificationBatch
	indices []int
}

func unscored(status, reason string) *ClassificationResult {
	return &ClassificationResult{Status: status, Reason: reason, PolicyVersion: ClassificationPolicyVersion}
}

func probabilityLabel(p float64) string {
	if p >= .9 {
		return "likely_real"
	}
	if p <= .1 {
		return "likely_dummy"
	}
	return "uncertain"
}

func (s *Scanner) enrich(parent context.Context, root string, results []ScanResult) {
	started := time.Now()
	o := s.Classification
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	capCandidates := o.MaxCandidates
	if capCandidates == 0 {
		capCandidates = 1000
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if j, ok := o.Classifier.(*JevClassifier); ok {
		j.ResetMemory()
		defer j.ResetMemory()
	}
	metrics := &ClassificationMetrics{}
	s.Metrics.Classification = metrics
	defer func() { metrics.Duration = time.Since(started) }()
	base := root
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		base = filepath.Dir(root)
	}
	chosen := candidateHeap{}
	for i := range results {
		r := &results[i]
		r.Classification = nil
		if !r.RuleEntropyThresholdMet && !o.AllCandidates && !o.IncludeLowEntropy {
			continue
		}
		metrics.Eligible++
		r.Classification = unscored("skipped", "candidate_limit")
		rel, err := filepath.Rel(base, r.FilePath)
		if err != nil {
			r.Classification.Reason = "invalid_path"
			continue
		}
		p := r.provenance
		if p == nil {
			r.Classification.Reason = "missing_provenance"
			continue
		}
		c := selectedCandidate{i, filepath.ToSlash(rel), r.LineNumber, p.start, p.end, r.RuleID}
		if len(chosen) < capCandidates {
			heap.Push(&chosen, c)
		} else if lessCandidate(c, chosen[0]) {
			chosen[0] = c
			heap.Fix(&chosen, 0)
		}

	}
	sort.Slice(chosen, func(i, j int) bool { return lessCandidate(chosen[i], chosen[j]) })
	files := make(chan []selectedCandidate)
	batches := make(chan preparedBatch, 8)
	var readers, workers sync.WaitGroup
	for n := 0; n < 2; n++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for group := range files {
				prepared := prepareClassificationFile(ctx, results, group, metrics)
				for _, b := range prepared {
					select {
					case batches <- b:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	for n := 0; n < 4; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for b := range batches {
				if ctx.Err() != nil {
					continue
				}
				answer, err := o.Classifier.ClassifyBatch(ctx, b.batch)
				atomic.AddInt64(&metrics.Requests, answer.Requests)
				atomic.AddInt64(&metrics.Retries, answer.Retries)
				atomic.AddInt64(&metrics.InputTokens, answer.InputTokens)
				atomic.AddInt64(&metrics.OutputTokens, answer.OutputTokens)
				reason := "provider_error"
				if e, ok := err.(*ClassificationError); ok {
					reason = e.Code
				}
				valid := err == nil && len(answer.Probabilities) == len(b.indices) && answer.Model != ""
				for _, p := range answer.Probabilities {
					if !validProbability(p) {
						valid = false
					}
				}
				for j, i := range b.indices {
					if !valid {
						if err == nil {
							reason = "invalid_response"
						}
						if reason == "budget_exhausted" || reason == "request_too_large" {
							results[i].Classification = unscored("skipped", reason)
						} else {
							results[i].Classification = unscored("error", reason)
						}
						continue
					}
					p := answer.Probabilities[j]
					results[i].Classification = &ClassificationResult{Status: "scored", RealSecretProbability: &p, Label: probabilityLabel(p), Model: answer.Model, PolicyVersion: ClassificationPolicyVersion, Source: answer.Source, ContextTruncated: b.batch.Truncated}
				}
			}
		}()
	}
	for i := 0; i < len(chosen); {
		j := i + 1
		for j < len(chosen) && chosen[j].path == chosen[i].path {
			j++
		}
		for _, c := range chosen[i:j] {
			results[c.index].Classification = unscored("skipped", "budget_exhausted")
		}
		select {
		case files <- chosen[i:j]:
		case <-ctx.Done():
			i = len(chosen)
			continue
		}
		i = j
	}
	close(files)
	readers.Wait()
	close(batches)
	workers.Wait()
	for i := range results {
		c := results[i].Classification
		if c == nil {
			continue
		}
		switch c.Status {
		case "scored":
			metrics.Scored++
			if c.Label == "uncertain" {
				metrics.Uncertain++
			}
			if c.Source == "cache" || c.Source == "memory" {
				metrics.CacheHits++
			}
		case "error":
			metrics.Failed++
		default:
			metrics.Skipped++
		}
	}
}
