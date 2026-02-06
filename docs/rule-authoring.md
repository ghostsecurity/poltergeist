# Rules

Guidelines for write Poltergeist rules.

## Strategies

There are two main strategies for writing secret detection patterns:

- Explicit secret format, when the format is known and static
- Variable declaration detection (targeting likely ways the secret might be declared as a variable)

In general, we prefer to write more rules that are more precise, more specific, and easier to reason about, rather than fewer rules that are more general. The performance penalty of more rules is negligible.

### Explicit secret format

When the format is known and static, we can use a regex pattern to match the secret. Often these types of secrets have a known prefix, a fixed length, and sometimes a magic string (e.g. OpenAI API keys have a magic string `T3BlbkFJ`).

### Variable declaration detection

When the format is not known, we look for likely ways the secret might be present in source code when declared as a variable. We look for variables that are unique to the secret provider. For example, Azure Storage Account keys are a fixed length, but no predictable format. We try to match variations on `Azure` (case insensitive) and a high entropy fixed length string. Avoid generic variable names like `TOKEN` as it will be more difficult to map back to a specific secret provider.

#### Capture group

Currently we only expect one capture group from the regex pattern. If the secret is a known format, the capture group should be just the secret itself.

The Huggingface rule, for example:

```
(?x)
  \b
    (hf_(?i)[A-Z0-9]{34})
  \b
```

Matches the token like `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` exactly.

However, if we are looking for a variable declaration secret, we capture the variable name in addition to the secret value.

The Clearbit rule, for example:

```
(?x)
  \b
    (
      (?i)clearbit\w*(?:token|key|secret)\w*
      [\W]{0,40}?
      [A-Z0-9_-]{35}
    )
  \b
```

Matches the `CLEARBIT_TOKEN` variable as well as the secret value in the case of `export CLEARBIT_TOKEN="td3aCzKhouIIgiua1d6Yvl5veaTNHMFbb7H"`.

Though this lowers the entropy of the match overall, it allows us to see (even in redacted logs) more information about the match. It is easier to understand how to match occurred and potentially if/how the match is a false positive.

#### Non-word matcher

We enlarged the non-word matcher from 10 to 40 characters to allow for more whitespace between the variable name and the secret(`[\W]{0,10}?` -> `[\W]{0,40}?`).

### Backwards compatibility

Do not change rule numbers. If a rule needs to be deprecated, delete it without changing the number of other rules.

## YAML Format

Example Poltergeist rule file:

```yaml
rules:
  - name: Anthropic API Key
    id: ghost.anthropic.1
    description: Matches an Anthropic API key.
    tags:
      - api
      - anthropic
    pattern: |
      (?x)
        \b
          (sk-ant-api\d{2}-(?i)[A-Z0-9_-]{86}-(?i)[A-Z0-9_]{6}AA)
        \b
    entropy: 5.1
    redact: [16, 4]
    tests:
      assert:
        - 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
      assert_not:
        - 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
    history:
      - 2025-08-02 initial version
```

### Rule Components

**Required**

- `name`: The name of the rule
- `id`: Globally unique identifier for the rule
- `description`: The description of the rule. This is user facing content
- `tags`: The tags used to categorize the rule
- `pattern`: The regex pattern for matching
- `entropy`: The minimum entropy threshold for matches
- `redact`: The prefix and suffix of the match to preserve, redact the rest
- `tests`: The test cases for rule validation
- `history`: The change history of the rule (at least one entry)

**Optional**

- `refs`: URLs of external resources supporting the secret detection approach or explaining when/where/how the secret is typically used
- `notes`: Ghost internal notes

## False Positive Mitigation

We employ some common techniques to reduce false positives in real-time during the scan.

### Boundaries

Use word boundaries (`\b`) when possible to reduce false positives. Word boundaries indicate where non-word characters occur. This helps prevent false positives from matching in the middle of a word.

### Entropy

Use entropy to filter out false positives. True secrets, keys, and cryptographic material should have high entropy. Specifying the `entropy` field forces the rule to only match secrets with an entropy greater than or equal to the specified value.

The calculated Shannon entropy and the rule threshold are both included in the output, allowing you to see exactly why a match was flagged or filtered.

### Stop Words

Stop words are words that are common in the English language and should not appear in most valid secrets.

⚠️ **Not implemented**: we aren't yet checking for stop words in the match.

## Redaction

The redaction points are the prefix and suffix of the match to preserve, the rest of the match is redacted.

For example, if the match is `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`, and the redaction points are `[16, 6]`, the redacted match will be:

```
sk-ant-api03-bvf*****pzoAAA
```

The first `16` and the last `6` characters are preserved. The rest of the match is redacted.

## Performance Tips

1. **Use specific patterns**: More specific regex patterns are faster than broad ones
2. **Boundaries**: Use `\b` boundaries in regex patterns when possible to reduce false positives
