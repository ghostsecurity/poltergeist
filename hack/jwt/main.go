package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// This is a hack to find base64-encoded fragments of a string in a JWT or base64-encoded string.
func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <jwt_or_base64_string> <search_string>")
		fmt.Println("Example: go run main.go eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6InlvdXItYXBwLWlkIiwiZXhwIjoxNjMwNTAwMDAwfQ.signature \"accounts.google.com\"")
		os.Exit(1)
	}

	token := os.Args[1]
	searchString := os.Args[2]

	found, matchedPattern := findBase64PatternsInToken(token, searchString)
	if found {
		fmt.Printf("✅ Found '%s' in the token (matched pattern: %s)\n", searchString, matchedPattern)
	} else {
		fmt.Printf("❌ '%s' not found in the token\n", searchString)
	}
}

// findBase64PatternsInToken searches for base64-encoded fragments of the search string in the raw token
func findBase64PatternsInToken(token, searchString string) (bool, string) {
	fmt.Printf("🔍 Searching for base64 patterns of '%s' in raw token...\n", searchString)

	// Generate all possible base64 encodings of the search string and its substrings
	patterns := generateBase64Patterns(searchString)

	fmt.Printf("📋 Generated %d base64 patterns to search for\n", len(patterns))
	for _, pattern := range patterns {
		fmt.Printf("   - %s\n", pattern)
	}

	// Search for each pattern in the raw token
	for _, pattern := range patterns {
		if strings.Contains(token, pattern) {
			return true, pattern
		}
	}

	return false, ""
}

// generateBase64Patterns generates all possible base64 encodings of a string and its substrings
func generateBase64Patterns(s string) []string {
	patterns := make(map[string]bool) // Use map to avoid duplicates

	// Generate patterns for the full string and all substrings of length >= 3
	for i := 0; i < len(s); i++ {
		for j := i + 3; j <= len(s); j++ { // Minimum 3 chars for meaningful base64
			substring := s[i:j]

			// Generate base64 encodings with different padding contexts
			// This accounts for the fact that the string might appear at different
			// byte boundaries within a larger JSON structure

			// Pattern 1: String as-is
			patterns[base64.StdEncoding.EncodeToString([]byte(substring))] = true
			patterns[base64.URLEncoding.EncodeToString([]byte(substring))] = true

			// Pattern 2: String with 1 prefix char (simulates being inside JSON)
			for _, prefix := range []string{"\"", ",", ":", "{", "}"} {
				prefixed := prefix + substring
				patterns[base64.StdEncoding.EncodeToString([]byte(prefixed))] = true
				patterns[base64.URLEncoding.EncodeToString([]byte(prefixed))] = true
			}

			// Pattern 3: String with 2 prefix chars
			for _, prefix := range []string{"\",", "\":", ":\"", ",\""} {
				prefixed := prefix + substring
				patterns[base64.StdEncoding.EncodeToString([]byte(prefixed))] = true
				patterns[base64.URLEncoding.EncodeToString([]byte(prefixed))] = true
			}

			// Pattern 4: String with suffix chars
			for _, suffix := range []string{"\"", ",", ":", "}", "\","} {
				suffixed := substring + suffix
				patterns[base64.StdEncoding.EncodeToString([]byte(suffixed))] = true
				patterns[base64.URLEncoding.EncodeToString([]byte(suffixed))] = true
			}
		}
	}

	// Convert map to slice and remove padding for partial matches
	var result []string
	for pattern := range patterns {
		// Add the full pattern
		result = append(result, pattern)

		// Also add patterns without padding (for partial matches at boundaries)
		trimmed := strings.TrimRight(pattern, "=")
		if len(trimmed) >= 4 { // Only add if it's still meaningful
			result = append(result, trimmed)
		}
	}

	return result
}
