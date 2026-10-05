package poltergeist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type recordingClassifier struct {
	calls   atomic.Int64
	batches chan ClassificationBatch
}

func (r *recordingClassifier) ClassifyBatch(ctx context.Context, b ClassificationBatch) (ClassificationBatchResult, error) {
	r.calls.Add(1)
	if r.batches != nil {
		r.batches <- b
	}
	p := make([]float64, len(b.Candidates))
	for i := range p {
		p[i] = .95
	}
	return ClassificationBatchResult{Probabilities: p, Model: DefaultJevModel, Source: "live"}, nil
}
func testScanner(t testing.TB) *Scanner {
	t.Helper()
	e := NewGoRegexEngine()
	if err := e.CompileRules([]Rule{{ID: "test.token", Name: "Token", Pattern: `secret=[A-Za-z0-9]+`, Entropy: 0}}); err != nil {
		t.Fatal(err)
	}
	return NewScanner(e)
}
func TestClassificationOptIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.go")
	if err := os.WriteFile(path, []byte("// heading\né secret=Abcd1234 secret=Zyx9876\n// after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := testScanner(t)
	results, err := s.ScanDirectory(dir)
	if err != nil || len(results) != 2 {
		t.Fatalf("baseline: %v %d", err, len(results))
	}
	for _, r := range results {
		if r.Match != "" || r.Classification != nil || r.provenance != nil {
			t.Fatal("opt-out retained sensitive data")
		}
	}
	classifier := &recordingClassifier{batches: make(chan ClassificationBatch, 8)}
	s.Classification = &ClassificationOptions{Classifier: classifier}
	results, err = s.ScanDirectory(dir)
	if err != nil || len(results) != 2 {
		t.Fatalf("enriched: %v", err)
	}
	for _, r := range results {
		if r.Match != "" || r.Classification.Label != "likely_real" || r.provenance != nil {
			t.Fatal("incorrect annotation")
		}
	}
	batch := <-classifier.batches
	if len(batch.Candidates) != 2 || batch.Candidates[0].Start == batch.Candidates[1].Start {
		t.Fatal("incorrect target mapping")
	}
	data, _ := json.Marshal(results)
	if strings.Contains(string(data), "Abcd1234") || strings.Contains(string(data), "heading") {
		t.Fatal("source leaked into output")
	}
	if s.Metrics.Classification.Scored != 2 {
		t.Fatal("incorrect metrics")
	}
}
func TestClassificationSelectionAndEligibility(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"z.go", "a.go", "m.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("secret=ABC\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := testScanner(t)
	classifier := &recordingClassifier{batches: make(chan ClassificationBatch, 8)}
	s.Classification = &ClassificationOptions{Classifier: classifier, MaxCandidates: 1}
	results, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b := <-classifier.batches; b.Candidates[0].Path != "a.go" {
		t.Fatal("selection depends on worker order")
	}
	if len(results) != 3 || s.Metrics.Classification.Skipped != 2 {
		t.Fatal("candidate cap changed findings")
	}
	for _, label := range []struct {
		p    float64
		want string
	}{{0, "likely_dummy"}, {.1, "likely_dummy"}, {.5, "uncertain"}, {.9, "likely_real"}, {1, "likely_real"}} {
		if probabilityLabel(label.p) != label.want {
			t.Fatal("label boundary")
		}
	}
	for i := range results {
		results[i].RuleEntropyThresholdMet = false
	}
	s.enrich(context.Background(), dir, results)
	if s.Metrics.Classification.Eligible != 0 {
		t.Fatal("low entropy eligible by default")
	}
}
func TestClassificationFileChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.go")
	if err := os.WriteFile(path, []byte("secret=ABC\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := testScanner(t)
	s.Classification = &ClassificationOptions{Classifier: &recordingClassifier{}}
	results, err := s.scanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("secret=DEF\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.enrich(context.Background(), dir, results)
	if results[0].Classification.Status != "skipped" || results[0].Classification.Reason != "file_changed" {
		t.Fatal("changed source scored")
	}
}
func testBatch() ClassificationBatch {
	return ClassificationBatch{Context: []ClassificationLine{{Number: 1, Text: "secret=Abcd1234"}}, Candidates: []ClassificationCandidate{{Path: "a.go", Line: 1, Start: 0, End: 15, Value: "secret=Abcd1234", RuleID: "test.token"}}}
}
func writeJevAnswer(w http.ResponseWriter, r *http.Request, p float64) {
	var req jevRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		w.WriteHeader(400)
		return
	}
	answers := map[string]any{}
	for id := range req.Questions {
		answers[id] = map[string]any{"type": "noul", "noul": p}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"model": req.Model, "answers": answers, "usage": map[string]int{"input_tokens": 100, "output_tokens": 4}})
}
func TestJevCacheIdentityAndExpiry(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing auth")
		}
		writeJevAnswer(w, r, .95)
	}))
	defer server.Close()
	dir := filepath.Join(t.TempDir(), "cache")
	newClient := func() *JevClassifier {
		j, err := NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: server.URL, CacheDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	j := newClient()
	batch := testBatch()
	first, err := j.ClassifyBatch(context.Background(), batch)
	if err != nil || first.Source != "live" || first.InputTokens != 100 {
		t.Fatalf("first result: %v %v", first, err)
	}
	second, err := newClient().ClassifyBatch(context.Background(), batch)
	if err != nil || second.Source != "cache" || calls.Load() != 1 {
		t.Fatal("disk cache missed")
	}
	batch.Context[0].Text = "// changed secret=Abcd1234"
	if _, err := j.ClassifyBatch(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("context change reused cache")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "Abcd1234") || strings.Contains(string(data), "a.go") || strings.Contains(string(data), "test-key") {
			t.Fatal("cache stored sensitive data")
		}
		if strings.HasSuffix(e.Name(), ".json") {
			var entry cacheEntry
			if json.Unmarshal(data, &entry) != nil {
				t.Fatal("invalid cache")
			}
			entry.Created = time.Now().Add(-25 * time.Hour)
			data, _ = json.Marshal(entry)
			if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := newClient().ClassifyBatch(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("expired cache reused")
	}
}
func TestJevResponseValidation(t *testing.T) {
	for _, body := range []string{
		`{"model":"jev-1.13.0","answers":{"candidate_0":{"type":"noul"}}}`,
		`{"model":"jev-1.13.0","answers":{"candidate_0":{"type":"noul","noul":1.2}}}`,
		`{"model":"jev-latest","answers":{"candidate_0":{"type":"noul","noul":0.9}}}`,
		`{"model":"jev-1.13.0","answers":{"wrong":{"type":"noul","noul":0.9}}}`,
		`private provider response secret=Abcd1234`,
	} {
		t.Run(fmt.Sprintf("case-%d", len(body)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			j, err := NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			_, err = j.ClassifyBatch(context.Background(), testBatch())
			if err == nil || err.Error() != "classification: invalid_response" {
				t.Fatalf("unsafe or missing error: %v", err)
			}
		})
	}
	if _, err := NewJevClassifier(JevOptions{APIKey: "test-key", Model: "jev-latest"}); err == nil {
		t.Fatal("model alias accepted")
	}
}
func TestJevRetryAndCancellation(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(529)
			return
		}
		writeJevAnswer(w, r, 0)
	}))
	defer server.Close()
	j, err := NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := j.ClassifyBatch(context.Background(), testBatch())
	if err != nil || answer.Requests != 2 || answer.Retries != 1 || answer.Probabilities[0] != 0 {
		t.Fatalf("retry: %v %v", answer, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	j.ResetMemory()
	if _, err = j.ClassifyBatch(ctx, testBatch()); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestJevAuthenticationStopsCalls(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(401)
		_, _ = w.Write([]byte("private response"))
	}))
	defer server.Close()
	j, err := NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		batch := testBatch()
		batch.Candidates[0].Path = fmt.Sprint(n)
		_, err := j.ClassifyBatch(context.Background(), batch)
		if err == nil {
			t.Fatal("missing auth error")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("auth failure retried")
	}
}
func BenchmarkClassificationDisabled(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(strings.Repeat("nothing sensitive here\n", 100)), 0600); err != nil {
		b.Fatal(err)
	}
	s := testScanner(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.ScanDirectory(dir); err != nil {
			b.Fatal(err)
		}
	}
}

func TestClassificationContextLimits(t *testing.T) {
	for _, line := range []string{
		strings.Repeat("x", 9000) + " secret=Abcd1234 " + strings.Repeat("y", 9000),
		strings.Repeat("x", 32767) + "\r\nsecret=Abcd1234\r\n",
		"secret=Abcd1234\r\n",
	} {
		t.Run(fmt.Sprint(len(line)), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.go")
			if err := os.WriteFile(path, []byte(line), 0600); err != nil {
				t.Fatal(err)
			}
			s := testScanner(t)
			c := &recordingClassifier{batches: make(chan ClassificationBatch, 8)}
			s.Classification = &ClassificationOptions{Classifier: c}
			results, err := s.ScanDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || results[0].Classification.Status != "scored" {
				t.Fatalf("context preparation failed: %+v", results)
			}
			batch := <-c.batches
			total := 0
			for _, l := range batch.Context {
				total += len(l.Text)
				if l.Number == batch.Candidates[0].Line {
					target := batch.Candidates[0]
					start, end := target.Start-l.StartByte, target.End-l.StartByte
					if start < 0 || end > len(l.Text) || l.Text[start:end] != target.Value {
						t.Fatal("cropped span incorrect")
					}
				}
			}
			if total > maxContextBytes {
				t.Fatal("context exceeded limit")
			}
		})
	}
}

func TestClassificationOversizedCandidate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("secret="+strings.Repeat("A", 3000)), 0600); err != nil {
		t.Fatal(err)
	}
	s := testScanner(t)
	c := &recordingClassifier{}
	s.Classification = &ClassificationOptions{Classifier: c}
	results, err := s.ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.calls.Load() != 0 || results[0].Classification.Reason != "candidate_too_large" {
		t.Fatal("oversized secret submitted")
	}
}

type waitingClassifier struct{}

func (waitingClassifier) ClassifyBatch(ctx context.Context, b ClassificationBatch) (ClassificationBatchResult, error) {
	<-ctx.Done()
	return ClassificationBatchResult{}, &ClassificationError{Code: "budget_exhausted"}
}
func TestClassificationBudget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("secret=Abcd1234"), 0600); err != nil {
		t.Fatal(err)
	}
	s := testScanner(t)
	s.Classification = &ClassificationOptions{Classifier: waitingClassifier{}, Timeout: 20 * time.Millisecond}
	start := time.Now()
	results, err := s.ScanDirectory(dir)
	if err != nil || len(results) != 1 || results[0].Classification.Status != "skipped" || time.Since(start) > time.Second {
		t.Fatal("budget failed to preserve findings")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ScanDirectoryContext(ctx, dir); err == nil {
		t.Fatal("detection cancellation ignored")
	}
}
func TestCacheConcurrentInitialization(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	done := make(chan *classificationCache, 16)
	for n := 0; n < 16; n++ {
		go func() { done <- openClassificationCache(dir) }()
	}
	var key string
	for n := 0; n < 16; n++ {
		c := <-done
		if c == nil {
			t.Fatal("initialization failed")
		}
		if key == "" {
			key = string(c.key)
		} else if key != string(c.key) {
			t.Fatal("inconsistent cache key")
		}
	}
}
func TestJevConcurrentDeduplication(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); writeJevAnswer(w, r, .5) }))
	defer server.Close()
	j, err := NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 8)
	for n := 0; n < 8; n++ {
		go func() { _, err := j.ClassifyBatch(context.Background(), testBatch()); done <- err }()
	}
	for n := 0; n < 8; n++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate concurrent requests")
	}
}
func TestJevRedirectAndRetryAfter(t *testing.T) {
	var destinationCalls atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer server.Close()
	j, err := NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ClassifyBatch(context.Background(), testBatch()); err == nil || destinationCalls.Load() != 0 {
		t.Fatal("redirect followed")
	}
	rate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "60"); w.WriteHeader(429) }))
	defer rate.Close()
	j, err = NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: rate.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	answer, err := j.ClassifyBatch(ctx, testBatch())
	if err == nil || answer.Requests != 1 {
		t.Fatal("retry exceeded budget")
	}
}

func TestClassificationWindowMerging(t *testing.T) {
	a := []ClassificationLine{{Number: 1, Text: "one"}, {Number: 2, Text: "two"}}
	b := []ClassificationLine{{Number: 2, Text: "two"}, {Number: 3, Text: "three"}}
	if union, ok := mergeWindows(a, b); !ok || len(union) != 3 {
		t.Fatal("overlapping context not merged")
	}
	b[0].Text = "different"
	if _, ok := mergeWindows(a, b); ok {
		t.Fatal("inconsistent context merged")
	}
	if _, ok := mergeWindows(a, []ClassificationLine{{Number: 8, Text: "distant"}}); ok {
		t.Fatal("unrelated context merged")
	}
}
func TestJevRequestLimitsAndRate(t *testing.T) {
	j, err := NewJevClassifier(JevOptions{APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	batch := testBatch()
	batch.Context[0].Text = strings.Repeat("x", 20*1024)
	if _, err := j.ClassifyBatch(context.Background(), batch); err == nil {
		t.Fatal("oversized request accepted")
	}
	started := time.Now()
	for n := 0; n < 3; n++ {
		if err := j.reserve(context.Background(), 16384); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(started) < 490*time.Millisecond {
		t.Fatal("byte rate exceeded")
	}
}
func TestClassificationRereadCap(t *testing.T) {
	metrics := &ClassificationMetrics{RereadBytes: maxRereadBytes - 3}
	reader := budgetReader{context.Background(), strings.NewReader("abcdef"), metrics}
	buffer := make([]byte, 10)
	n, err := reader.Read(buffer)
	if err != nil || n != 3 || metrics.RereadBytes != maxRereadBytes {
		t.Fatal("reread cap exceeded")
	}
	if _, err := reader.Read(buffer); err == nil {
		t.Fatal("exhausted reread allowed")
	}
}
func TestCacheCorruptionAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	cache := openClassificationCache(dir)
	if cache == nil {
		t.Fatal("cache unavailable")
	}
	identity := []byte("request")
	cache.put(context.Background(), identity, ClassificationBatchResult{Model: DefaultJevModel, Probabilities: []float64{.9}})
	path := cache.name(identity)
	if err := os.WriteFile(path, []byte("bad JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.get(context.Background(), identity, DefaultJevModel, 1); ok {
		t.Fatal("corrupt entry accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if openClassificationCache(dir) != nil {
		t.Fatal("public directory accepted")
	}
}

func BenchmarkClassificationScenarios(b *testing.B) {
	for _, scenario := range []string{"no-findings", "sparse", "dense", "cold-cache", "warm-cache", "unavailable"} {
		b.Run(scenario, func(b *testing.B) {
			dir := b.TempDir()
			content := strings.Repeat("nothing sensitive here\n", 100)
			switch scenario {
			case "sparse", "cold-cache", "warm-cache", "unavailable":
				content += "secret=Abcd1234\n"
			case "dense":
				content = strings.Repeat("secret=Abcd1234\n", 100)
			}
			if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(content), 0600); err != nil {
				b.Fatal(err)
			}
			s := testScanner(b)
			if scenario == "cold-cache" || scenario == "warm-cache" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJevAnswer(w, r, .9) }))
				defer server.Close()
				j, err := NewJevClassifier(JevOptions{APIKey: "test-key", Endpoint: server.URL, CacheDir: filepath.Join(b.TempDir(), "cache")})
				if err != nil {
					b.Fatal(err)
				}
				s.Classification = &ClassificationOptions{Classifier: j}
				if scenario == "warm-cache" {
					if _, err := s.ScanDirectory(dir); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					if scenario == "cold-cache" {
						b.StopTimer()
						entries, _ := os.ReadDir(j.cache.dir)
						for _, e := range entries {
							if strings.HasSuffix(e.Name(), ".json") {
								_ = os.Remove(filepath.Join(j.cache.dir, e.Name()))
							}
						}
						b.StartTimer()
					}
					if _, err := s.ScanDirectory(dir); err != nil {
						b.Fatal(err)
					}
				}
				return
			}
			if scenario == "unavailable" {
				s.Classification = &ClassificationOptions{Classifier: waitingClassifier{}, Timeout: time.Millisecond}
			} else {
				s.Classification = &ClassificationOptions{Classifier: &recordingClassifier{}}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if _, err := s.ScanDirectory(dir); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestClassificationLowEntropyCoverage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("secret=AAAAAAAAA\n"), 0600); err != nil {
		t.Fatal(err)
	}
	engine := NewGoRegexEngine()
	if err := engine.CompileRules([]Rule{{ID: "test.low", Pattern: `secret=[A-Z]+`, Entropy: 10}}); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(engine)
	c := &recordingClassifier{}
	s.Classification = &ClassificationOptions{Classifier: c}
	results, err := s.ScanDirectory(dir)
	if err != nil || len(results) != 1 || results[0].Classification != nil || c.calls.Load() != 0 {
		t.Fatal("hidden candidate submitted")
	}
	s.Classification.AllCandidates = true
	results, err = s.ScanDirectory(dir)
	if err != nil || len(results) != 1 || results[0].Classification.Status != "scored" {
		t.Fatal("all candidates not scored")
	}
	s.Classification.AllCandidates = false
	s.Classification.IncludeLowEntropy = true
	results, err = s.ScanDirectory(dir)
	if err != nil || results[0].Classification.Status != "scored" {
		t.Fatal("report coverage ignored")
	}
}
func TestClassificationMalformedTargetLine(t *testing.T) {
	dir := t.TempDir()
	content := append([]byte{0xff}, []byte("secret=Abcd1234")...)
	if err := os.WriteFile(filepath.Join(dir, "a.go"), content, 0600); err != nil {
		t.Fatal(err)
	}
	s := testScanner(t)
	c := &recordingClassifier{}
	s.Classification = &ClassificationOptions{Classifier: c}
	results, err := s.ScanDirectory(dir)
	if err != nil || len(results) != 1 {
		t.Fatal("malformed fixture failed")
	}
	if c.calls.Load() != 0 || results[0].Classification.Reason != "invalid_encoding" {
		t.Fatal("invalid byte mapping submitted")
	}
}
func TestCacheStorageBound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	cache := openClassificationCache(dir)
	if cache == nil {
		t.Fatal("cache unavailable")
	}
	for n := 0; n < 3; n++ {
		name := filepath.Join(dir, fmt.Sprintf("%064d.json", n))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(33 * 1024 * 1024); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	cache.put(context.Background(), []byte("new-request"), ClassificationBatchResult{Model: DefaultJevModel, Probabilities: []float64{.9}})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			total += info.Size()
		}
	}
	if total > classificationCacheLimit {
		t.Fatal("cache exceeded storage bound")
	}
}
