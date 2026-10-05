# Advisory secret classification

Poltergeist can ask TypeSafe's Jev model whether a detected value appears to be
an authentic secret. Classification is disabled by default. Enabling it sends
**raw matched values, bounded surrounding source, rule identifiers/names, and
relative file paths** to the TypeSafe API, even when report redaction is enabled.
`TYPESAFE_API_KEY` alone never enables submission.

```sh
export TYPESAFE_API_KEY='your-api-key'
poltergeist -classify -format json ./source
poltergeist -classify -classify-timeout 5s -classify-max-candidates 250 ./source
poltergeist -classify -classify-cache-dir ./private-classification-cache ./source
```

Do not put the cache directory inside the scanned source tree. The scanner does
not automatically exclude it. Use a dedicated private directory outside the tree.
The API key is read from the environment by the CLI, never supplied as a flag.

Classification is advisory: a likely dummy remains a finding. Existing entropy
filtering and finding-based exit codes remain in effect. By default only
entropy-passing candidates are submitted; `-low-entropy` makes low-entropy
candidates eligible too. `-classify-all` submits eligible regex matches even when
the report hides them for low entropy. It requires `-classify` to have an effect.

## Reading the result

Each scored finding has a `classification` object containing:

- `real_secret_probability`: the Jev Noul probability, from zero to one.
- `label`: `likely_real` at or above 0.90, `likely_dummy` at or below 0.10,
  otherwise `uncertain`.
- `status`: `scored`, `skipped`, or `error`.
- `model`, `policy_version`, `source` (`live`, `cache`, or `memory`), and
  `context_truncated` when context was cropped.

Unscored findings have a reason code and no probability. A missing probability
is not zero. `uncertain` is a completed model judgment; `skipped` means no usable
judgment was available, for example because the budget expired or the file changed.
`error` identifies provider failures or invalid responses. Classification metrics
appear at the top level of JSON reports and in text/Markdown summaries. Their
counts can include candidates hidden by entropy filtering when `-classify-all`
is used. Duration is enrichment wall time, excluding detection; JSON records it
in nanoseconds. Scan metrics otherwise retain their existing cumulative behavior.

An authentic secret includes development credentials and revoked/expired keys.
The score does not prove a credential is currently valid, identify its owner,
or verify it against the issuing service. It is a pretrained model judgment,
not a measured probability calibrated on Poltergeist's own labeled dataset.
Source comments can mislead the model, and real credentials can appear in tests
or documentation. Do not use the advisory labels as an automatic suppression policy.

## Resource limits

The default enrichment budget is ten seconds after detection, selecting at most
1,000 candidates by relative path, line, byte span, and rule ID. Report order is
preserved. The original scan workers never make HTTP calls.

Only selected files are reread, once per file. File identity, size, modification
time, and matched-line digest are checked before submission. Changed or unreadable
files remain findings with an unscored status. Metadata checks do not provide
transactional filesystem snapshots; use an immutable checkout for reproducibility.

Context includes up to five neighboring lines in either direction, capped at
8 KiB. Targets longer than 2 KiB are skipped. Long lines are cropped around the
complete target using UTF-8 boundaries; byte origins identify cropped spans.
Overlapping local windows can share a request, with at most 16 targets and
16 KiB of serialized JSON. Unrelated files are never combined. Some batches
contain fewer targets because questions themselves occupy request space.

There are two reread workers, four inference workers, an eight-batch queue, and
an aggregate reread cap of 64 MiB. The client schedules at most ten requests per
second and 64 KiB of request bodies per second, including retries. These limits
apply to a classifier instance, not to every process sharing the same account.

Each HTTP attempt has a two-second timeout. Connection failures, HTTP 408/429,
and 5xx responses (including 529) can retry twice with exponential backoff,
jitter, and retry-header handling, within the overall deadline. Authentication
failures stop further submissions. Redirects are rejected. Classification limits
and provider failures never remove findings. Filesystem cancellation is cooperative:
a stalled filesystem operation can delay returning past the requested deadline.

## Reproducibility and optional cache

The model is pinned to `jev-1.13.0`, with policy `secret-authenticity-v1`. The policy
versions the question, criteria, context extraction, request construction, and
label thresholds. Live numeric answers may vary; pinning is not a vendor guarantee
of identical responses. Model upgrades must use a versioned model ID and a new
policy version when the rubric or extraction changes; aliases are rejected.

In-memory request deduplication lasts for one scanner enrichment run. The optional
persistent cache reuses exact canonical requests for 24 hours. Keys include the
endpoint, model, policy, full shared context, paths, candidate ordering, and batch
composition. A changed batch cannot reuse an individual candidate's old score.

Cache filenames use HMAC with a randomly generated directory-local key. Entries
store probabilities, model, policy, and creation time; they contain no raw values,
source code, paths, or API keys. Initialization and writes are atomic, and pruning
is serialized across processes. Storage is capped at 64 MiB. Existing cache
directories must be private (no group/other permission bits); new directories use
0700 and files use 0600 on systems supporting POSIX permissions. Unsupported
permissions/filesystems, busy or stale write locks, inaccessible files, corrupt
entries, and expired entries cause nonfatal cache misses or skipped writes. Remove
a stale `.write-lock` only when no cache writer is running. Cache corruption never
silently supplies a zero score.

## Go library

```go
classifier, err := poltergeist.NewJevClassifier(poltergeist.JevOptions{
    APIKey: os.Getenv("TYPESAFE_API_KEY"),
    // CacheDir: "/private/path/to/classification-cache", // optional
})
if err != nil {
    return err
}
scanner := poltergeist.NewScanner(engine) // engine already has compiled rules
scanner.Classification = &poltergeist.ClassificationOptions{
    Classifier: classifier,
    Timeout: 10 * time.Second,
    MaxCandidates: 1000,
}
results, err := scanner.ScanDirectoryContext(ctx, sourcePath)
```

The library does not read credentials implicitly. Zero option limits select the
defaults. Negative limits or a nil enabled classifier are configuration errors.
`IncludeLowEntropy` mirrors report eligibility and `AllCandidates` overrides it.
Existing `ScanDirectory` also enriches when the configuration is enabled.

A Scanner cannot run concurrent scans or be reconfigured during scanning. An
injected `CandidateClassifier` must honor context cancellation, support concurrent
calls, and return probabilities aligned with the batch. Its errors should contain
only safe reason codes. The Jev adapter supports a custom HTTPS endpoint and HTTP
client; HTTP is accepted only for localhost testing. Scanner resets the adapter's
in-memory replay at enrichment boundaries; direct adapter callers may use
`ResetMemory` to define their own run boundary.

## Validation

Automated tests use fake local HTTP servers, never the hosted service. They cover
candidate mapping, redaction, limits, file changes, response validation, retries,
authentication, caching, concurrency, and cancellation. Optional live smoke tests
should use fabricated or inactive examples. No classification-accuracy claim is
made without a reviewed domain-specific evaluation dataset.
