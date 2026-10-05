package main

import (
	"encoding/json"
	poltergeist "github.com/ghostsecurity/poltergeist/v2/pkg"
	"strings"
	"testing"
	"time"
)

func TestClassificationOutputPreservesExitCodes(t *testing.T) {
	p := .01
	results := []poltergeist.ScanResult{{FilePath: "a.go", LineNumber: 1, Redacted: "****", RuleEntropyThresholdMet: true, Classification: &poltergeist.ClassificationResult{Status: "scored", RealSecretProbability: &p, Label: "likely_dummy", Model: poltergeist.DefaultJevModel, PolicyVersion: poltergeist.ClassificationPolicyVersion, Source: "live"}}}
	output, code := formatJSON(results, 1, 0, 10, 1, 0, &poltergeist.ClassificationMetrics{Scored: 1})
	if code != 1 || !json.Valid([]byte(output)) || !strings.Contains(output, "likely_dummy") {
		t.Fatal("invalid classified JSON or suppressed finding")
	}
	text, code := formatText(results, 1, 0, 10, 1, 0, time.Millisecond, false, false)
	if code != 1 || !strings.Contains(text, "likely_dummy") {
		t.Fatal("text missing classification")
	}
	markdown, code := formatMarkdown(results, ".", 1, 0, 10, 1, 0, time.Millisecond)
	if code != 1 || !strings.Contains(markdown, "- Classification: likely_dummy") {
		t.Fatal("markdown missing classification")
	}
	output, code = formatJSON(nil, 1, 0, 10, 0, 0)
	if code != 0 || strings.Contains(output, "classification") {
		t.Fatal("opt-out shape changed")
	}
}
