package bind

import (
	"strings"
	"testing"
)

// Every closed-set refusal must produce an actionable sentence: a refusal the
// display cannot explain is exactly how a reused connect link came to read as
// "an unexpected error occurred".
func TestDisplayPhraseCoversEveryClosedCategory(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		category string
		want     string
	}{
		{"ticket superseded", 409, CategoryTicketSuperseded, "generate a new connect link"},
		{"unauthorized", 401, "unauthorized", "generate a new connect link"},
		{"not found", 404, "not_found", "generate a new connect link"},
		{"request id conflict", 409, "conflict", "already used with a different request"},
		{"bad request", 400, "bad_request", "generate a new connect link"},
		{"invalid request", 422, "invalid_request", "generate a new connect link"},
		{"rate limited", 429, "rate_limited", "wait a moment"},
		{"server error", 500, "server_error", "try again shortly"},
		{"transport", 0, CategoryTransport, "could not be reached"},
		{"invalid response", 200, CategoryInvalidResponse, "could not be understood"},
		{"redirect", 302, "redirect", "redirect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &Error{msg: "refused", category: tc.category, status: tc.status}
			phrase := err.DisplayPhrase()
			if phrase == "" {
				t.Fatalf("category %q has no phrase", tc.category)
			}
			if !strings.Contains(phrase, tc.want) {
				t.Fatalf("phrase %q does not contain %q", phrase, tc.want)
			}
		})
	}
	if got := (&Error{category: CategoryOther}).DisplayPhrase(); got != "" {
		t.Fatalf("an unmapped category must return no phrase, got %q", got)
	}
}
