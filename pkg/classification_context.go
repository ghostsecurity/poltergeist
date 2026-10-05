package poltergeist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"sync/atomic"
	"unicode/utf8"
)

const maxContextBytes = 8 * 1024
const maxCandidateBytes = 2 * 1024
const maxRereadBytes = 64 * 1024 * 1024

type budgetReader struct {
	ctx     context.Context
	reader  io.Reader
	metrics *ClassificationMetrics
}

func (r budgetReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	// Reserve before reading so concurrent readers never exceed the global cap.
	for {
		used := atomic.LoadInt64(&r.metrics.RereadBytes)
		remaining := int64(maxRereadBytes) - used
		if remaining <= 0 {
			return 0, &ClassificationError{Code: "reread_limit"}
		}
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
		if atomic.CompareAndSwapInt64(&r.metrics.RereadBytes, used, used+int64(len(p))) {
			break
		}
	}
	n, err := r.reader.Read(p)
	atomic.AddInt64(&r.metrics.RereadBytes, -int64(len(p)-n))
	return n, err
}

type boundedLine struct {
	number    int
	text      string
	truncated bool
}

// Each selected file is read once. Retain only a rolling window and the bounded
// contexts for selected targets, never its full contents or an unlimited line.
func prepareClassificationFile(ctx context.Context, results []ScanResult, group []selectedCandidate, metrics *ClassificationMetrics) []preparedBatch {
	if len(group) == 0 {
		return nil
	}
	fail := func(reason string) {
		for _, c := range group {
			results[c.index].Classification = unscored("skipped", reason)
		}
	}
	file, err := os.Open(results[group[0].index].FilePath)
	if err != nil {
		fail("file_unavailable")
		return nil
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fail("file_unavailable")
		return nil
	}
	for _, c := range group {
		p := results[c.index].provenance
		if !sameFileVersion(info, p.info) {
			fail("file_changed")
			return nil
		}
	}
	// Scanner's existing 10 MiB line limit is retained for detection. Rereading
	// fragments through ReadSlice avoids allocating another full long line.
	reader := bufio.NewReaderSize(budgetReader{ctx, file, metrics}, 32*1024)
	targets := map[int][]selectedCandidate{}
	for _, c := range group {
		targets[c.line] = append(targets[c.line], c)
	}
	windows := map[int][]ClassificationLine{}
	truncation := map[int]bool{}
	values := map[int]string{}
	ring := make([]boundedLine, 0, 6)
	lastLine := group[len(group)-1].line + 5
	for lineNumber := 1; lineNumber <= lastLine; lineNumber++ {
		if ctx.Err() != nil {
			fail("budget_exhausted")
			return nil
		}
		lineTargets := targets[lineNumber]
		hash := sha256.New()
		var prefix []byte
		targetPieces := map[int][]byte{}
		targetSlices := map[int][]byte{}
		offset := 0
		eof := false
		var pending []byte
		for {
			fragment, readErr := reader.ReadSlice('\n')
			if readErr != nil && readErr != bufio.ErrBufferFull && readErr != io.EOF {
				reason := "file_unavailable"
				if e, ok := readErr.(*ClassificationError); ok {
					reason = e.Code
				}
				if ctx.Err() != nil {
					reason = "budget_exhausted"
				}
				fail(reason)
				return nil
			}
			// bufio.Scanner strips a trailing CR as well as LF. Hold the last byte
			// for finalization so hashes exactly match its line semantics.
			final := readErr != bufio.ErrBufferFull
			if len(pending) > 0 {
				fragment = append(pending, fragment...)
				pending = nil
			}
			if !final && len(fragment) > 0 {
				pending = append([]byte(nil), fragment[len(fragment)-1])
				fragment = fragment[:len(fragment)-1]
			}
			if final {
				if len(fragment) > 0 && fragment[len(fragment)-1] == '\n' {
					fragment = fragment[:len(fragment)-1]
				}
				if len(fragment) > 0 && fragment[len(fragment)-1] == '\r' {
					fragment = fragment[:len(fragment)-1]
				}
			}
			_, _ = hash.Write(fragment)
			if len(prefix) < maxContextBytes {
				n := min(len(fragment), maxContextBytes-len(prefix))
				prefix = append(prefix, fragment[:n]...)
			}
			for _, c := range lineTargets {
				p := results[c.index].provenance
				if p.start < 0 || p.end <= p.start || p.end-p.start > maxCandidateBytes {
					continue
				}
				left, right := max(p.start, offset), min(p.end, offset+len(fragment))
				if left < right {
					targetPieces[c.index] = append(targetPieces[c.index], fragment[left-offset:right-offset]...)
				}
				// A long target line is cropped around its exact span, with byte origin.
				left, right = max(0, p.start-2048), p.end+2048
				a, b := max(left, offset), min(right, offset+len(fragment))
				if a < b {
					targetSlices[c.index] = append(targetSlices[c.index], fragment[a-offset:b-offset]...)
				}
			}
			offset += len(fragment)
			if final {
				eof = readErr == io.EOF
				break
			}
		}
		if eof && offset == 0 {
			break
		}
		text := validPrefix(prefix)
		current := boundedLine{lineNumber, text, offset > len(prefix)}
		for i, w := range windows {
			cLine := results[i].LineNumber
			if lineNumber > cLine && lineNumber <= cLine+5 {
				next := append(w, ClassificationLine{Number: lineNumber, Text: text})
				var trimmed bool
				windows[i], trimmed = trimWindow(next, cLine)
				truncation[i] = truncation[i] || trimmed
				truncation[i] = truncation[i] || current.truncated
			}
		}
		for _, c := range lineTargets {
			p := results[c.index].provenance
			if p.start < 0 || p.end <= p.start || p.end > offset {
				results[c.index].Classification = unscored("skipped", "invalid_span")
				continue
			}
			if p.end-p.start > maxCandidateBytes {
				results[c.index].Classification = unscored("skipped", "candidate_too_large")
				continue
			}
			var digest [32]byte
			copy(digest[:], hash.Sum(nil))
			if digest != p.lineHash {
				results[c.index].Classification = unscored("skipped", "file_changed")
				continue
			}
			value := string(targetPieces[c.index])
			if !utf8.ValidString(value) {
				results[c.index].Classification = unscored("skipped", "invalid_encoding")
				continue
			}
			w := make([]ClassificationLine, 0, 11)
			for _, l := range ring {
				if l.number >= lineNumber-5 {
					w = append(w, ClassificationLine{Number: l.number, Text: l.text})
					truncation[c.index] = truncation[c.index] || l.truncated
				}
			}
			origin := 0
			targetText := text
			if current.truncated {
				origin = max(0, p.start-2048)
				raw := targetSlices[c.index]
				for len(raw) > 0 && !utf8.RuneStart(raw[0]) {
					raw = raw[1:]
					origin++
				}
				targetText = validPrefix(raw)
			}
			start, end := p.start-origin, p.end-origin
			if start < 0 || end > len(targetText) || targetText[start:end] != value {
				results[c.index].Classification = unscored("skipped", "invalid_encoding")
				continue
			}
			w = append(w, ClassificationLine{Number: lineNumber, Text: targetText, StartByte: origin})
			var trimmed bool
			windows[c.index], trimmed = trimWindow(w, lineNumber)
			truncation[c.index] = truncation[c.index] || trimmed
			values[c.index] = value
			truncation[c.index] = truncation[c.index] || current.truncated
		}
		ring = append(ring, current)
		if len(ring) > 5 {
			ring = ring[1:]
		}
		if eof {
			break
		}
	}
	after, err := file.Stat()
	pathInfo, pathErr := os.Stat(results[group[0].index].FilePath)
	if err != nil || pathErr != nil || !sameFileVersion(info, after) || !sameFileVersion(info, pathInfo) {
		fail("file_changed")
		return nil
	}
	var batches []preparedBatch
	for _, c := range group {
		w, ok := windows[c.index]
		if !ok {
			continue
		}
		w, trimmed := trimWindow(w, c.line)
		truncated := truncation[c.index] || trimmed
		candidate := ClassificationCandidate{Path: c.path, Line: c.line, Start: c.start, End: c.end, Value: values[c.index], RuleID: results[c.index].RuleID, RuleName: results[c.index].RuleName}
		// Merge adjacent overlapping windows only if the full union remains
		// bounded and the actual serialized inference request still fits.
		merged := false
		if len(batches) > 0 {
			previous := &batches[len(batches)-1]
			if len(previous.indices) < 16 {
				union, ok := mergeWindows(previous.batch.Context, w)
				if ok {
					trial := ClassificationBatch{Context: union, Candidates: append(append([]ClassificationCandidate(nil), previous.batch.Candidates...), candidate), Truncated: previous.batch.Truncated || truncated}
					if _, err := buildJevRequest(trial, DefaultJevModel); err == nil {
						previous.batch = trial
						previous.indices = append(previous.indices, c.index)
						merged = true
					}
				}
			}
		}
		if !merged {
			batches = append(batches, preparedBatch{ClassificationBatch{w, []ClassificationCandidate{candidate}, truncated}, []int{c.index}})
		}
	}
	return batches
}

func sameFileVersion(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
func validPrefix(b []byte) string {
	// Remove only an incomplete trailing rune; replace malformed interior bytes
	// in linear time rather than repeatedly validating progressively shorter text.
	if len(b) > 0 {
		start := len(b) - 1
		for start > 0 && len(b)-start < 4 && !utf8.RuneStart(b[start]) {
			start--
		}
		if !utf8.FullRune(b[start:]) {
			b = b[:start]
		}
	}
	return string(bytes.ToValidUTF8(b, []byte("�")))
}
func trimWindow(w []ClassificationLine, target int) ([]ClassificationLine, bool) {
	total := 0
	for _, l := range w {
		total += len(l.Text)
	}
	trimmed := false
	for total > maxContextBytes && len(w) > 1 {
		i := 0
		if w[0].Number == target || w[len(w)-1].Number-target > target-w[0].Number {
			i = len(w) - 1
		}
		total -= len(w[i].Text)
		if i == 0 {
			w = w[1:]
		} else {
			w = w[:len(w)-1]
		}
		trimmed = true
	}
	return w, trimmed
}
func mergeWindows(a, b []ClassificationLine) ([]ClassificationLine, bool) {
	if len(a) == 0 || len(b) == 0 || a[len(a)-1].Number < b[0].Number || b[len(b)-1].Number < a[0].Number {
		return nil, false
	}
	union := make([]ClassificationLine, 0, len(a)+len(b))
	i, j, total := 0, 0, 0
	for i < len(a) || j < len(b) {
		var line ClassificationLine
		switch {
		case j == len(b) || (i < len(a) && a[i].Number < b[j].Number):
			line = a[i]
			i++
		case i == len(a) || b[j].Number < a[i].Number:
			line = b[j]
			j++
		default:
			if a[i] != b[j] {
				return nil, false
			}
			line = a[i]
			i++
			j++
		}
		total += len(line.Text)
		if total > maxContextBytes {
			return nil, false
		}
		union = append(union, line)
	}
	return union, true
}
