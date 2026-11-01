package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"toktrail-collector/internal/bind"
	"toktrail-collector/internal/local/statedir"
)

// hostileTicket is a 64-hex-character connect ticket whose leading
// characters are letters, so the same value can be reflected into every
// server-controlled field under test (including a URL scheme).
const hostileTicket = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef0123"

// bearerTicket extracts the ticket fetchConnectConfig sent in the
// Authorization header, so a hostile handler can reflect the exact
// credential it saw back into response fields.
func bearerTicket(t *testing.T, r *http.Request) string {
	t.Helper()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= len("Bearer ") {
		t.Error("expected Authorization bearer header carrying the ticket")
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// assertNoTicketLeak renders err the ways a CLI surfaces errors to humans
// (direct printing plus %v/%w wrapping) and fails if the connect ticket
// appears in any rendering.
func assertNoTicketLeak(t *testing.T, err error, ticket string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected connect error")
	}
	for _, text := range []string{
		err.Error(),
		fmt.Sprint(err),
		fmt.Sprintf("%v", err),
		fmt.Errorf("connect: %w", err).Error(),
		fmt.Errorf("connect: %v", err).Error(),
	} {
		if ticket != "" && strings.Contains(text, ticket) {
			t.Fatalf("ticket leaked into error text: %q", text)
		}
	}
}

// hostileConfigServer serves whatever response fn produces, handing it the
// reflected bearer ticket.
func hostileConfigServer(t *testing.T, fn func(w http.ResponseWriter, ticket string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fn(w, bearerTicket(t, r))
	}))
}

// hostileConfigBody returns a fully valid connect config body with mutate
// applied, so each subtest only changes the field it is attacking.
func hostileConfigBody(mutate func(cfg map[string]any)) map[string]any {
	cfg := map[string]any{
		"schemaVersion": 1,
		"serverUrl":     "http://localhost:8080",
		"applicationId": "app-1",
		"subjectId":     "sub-1",
		"tools":         []string{"Codex"},
		"days":          30,
		"expiresAt":     time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

func TestFetchConnectConfigHostileReflectionsNeverLeakTicket(t *testing.T) {
	now := time.Now()

	t.Run("serverUrl_userinfo_secret", func(t *testing.T) {
		server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			cfg := hostileConfigBody(func(cfg map[string]any) {
				// A non-ticket secret: the ticket itself is covered by the
				// reflected-ticket gate in its own test below.
				cfg["serverUrl"] = "https://user:NotThisRunsTicket9@example.com/"
			})
			_ = json.NewEncoder(w).Encode(cfg)
		})
		defer server.Close()
		_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
		assertNoTicketLeak(t, err, hostileTicket)
		if !strings.Contains(err.Error(), "userinfo") {
			t.Fatalf("expected fixed userinfo category, got %q", err.Error())
		}
		if strings.Contains(err.Error(), "NotThisRunsTicket9") {
			t.Fatalf("server free-text password leaked: %q", err.Error())
		}
	})

	t.Run("serverUrl_unparseable_secret", func(t *testing.T) {
		server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			cfg := hostileConfigBody(func(cfg map[string]any) {
				cfg["serverUrl"] = "https://example.com/%zzProxySecret777"
			})
			_ = json.NewEncoder(w).Encode(cfg)
		})
		defer server.Close()
		_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
		assertNoTicketLeak(t, err, hostileTicket)
		if !strings.Contains(err.Error(), "not parseable") {
			t.Fatalf("expected fixed unparseable serverUrl category, got %q", err.Error())
		}
		if strings.Contains(err.Error(), "ProxySecret777") {
			t.Fatalf("raw server URL leaked: %q", err.Error())
		}
	})

	t.Run("serverUrl_scheme_secret", func(t *testing.T) {
		server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			cfg := hostileConfigBody(func(cfg map[string]any) {
				cfg["serverUrl"] = "fakescheme://example.com"
			})
			_ = json.NewEncoder(w).Encode(cfg)
		})
		defer server.Close()
		_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
		assertNoTicketLeak(t, err, hostileTicket)
		if !strings.Contains(err.Error(), "scheme") {
			t.Fatalf("expected fixed scheme category, got %q", err.Error())
		}
	})

	t.Run("malformed_json_reflected", func(t *testing.T) {
		server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			_, _ = w.Write([]byte("<<" + ticket + ">> this is not json"))
		})
		defer server.Close()
		_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
		assertNoTicketLeak(t, err, hostileTicket)
		if !strings.Contains(err.Error(), "invalid connect response JSON") {
			t.Fatalf("expected fixed JSON category, got %q", err.Error())
		}
	})

	t.Run("non_2xx_body_reflected", func(t *testing.T) {
		server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(ticket))
		})
		defer server.Close()
		_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
		assertNoTicketLeak(t, err, hostileTicket)
		if !strings.Contains(err.Error(), "status 403") {
			t.Fatalf("expected numeric status failure, got %q", err.Error())
		}
	})

	t.Run("expired_renders_parsed_time_only", func(t *testing.T) {
		server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			cfg := hostileConfigBody(func(cfg map[string]any) {
				cfg["expiresAt"] = "2020-01-02T03:04:05Z"
			})
			_ = json.NewEncoder(w).Encode(cfg)
		})
		defer server.Close()
		_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
		assertNoTicketLeak(t, err, hostileTicket)
		if !strings.Contains(err.Error(), "connect authorization expired at 2020-01-02T03:04:05Z") {
			t.Fatalf("expected normalized expiry time in error, got %q", err.Error())
		}
	})
}

// failingReadBody makes the config body read fail with a hostile error that
// carries secrets which are not this run's ticket.
type failingReadBody struct{ err error }

func (b *failingReadBody) Read([]byte) (int, error) { return 0, b.err }
func (b *failingReadBody) Close() error             { return nil }

// privRoundTripper adapts a function to http.RoundTripper for tests in this
// file.
type privRoundTripper func(*http.Request) (*http.Response, error)

func (f privRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchConnectConfigBodyReadErrorIsSanitized(t *testing.T) {
	readCause := errors.New("connection reset by peer: password=OtherProxySecret123 via proxy.internal:3128")
	client := &http.Client{Transport: privRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       &failingReadBody{err: readCause},
			Header:     make(http.Header),
		}, nil
	})}
	_, err := fetchConnectConfig(context.Background(), client, "http://127.0.0.1:1/x", hostileTicket, time.Now())
	if err == nil {
		t.Fatal("expected read error")
	}
	if !strings.Contains(err.Error(), "failed to read connect response body") {
		t.Fatalf("expected fixed read-error category, got %q", err.Error())
	}
	for _, text := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Errorf("connect: %w", err).Error()} {
		for _, marker := range []string{"OtherProxySecret123", "proxy.internal", "connection reset"} {
			if strings.Contains(text, marker) {
				t.Fatalf("read error text surfaced: %q", text)
			}
		}
	}
	if !errors.Is(err, readCause) {
		t.Fatal("expected read cause reachable via errors.Is")
	}
}

func TestFetchConnectConfigFailsClosedOnReflectedTicket(t *testing.T) {
	now := time.Now()
	serve := func(t *testing.T, mutate func(cfg map[string]any, ticket string)) *httptest.Server {
		t.Helper()
		return hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			cfg := hostileConfigBody(nil)
			mutate(cfg, ticket)
			_ = json.NewEncoder(w).Encode(cfg)
		})
	}
	// assertReflectedTicketRejected fails unless the config is rejected with
	// the fixed reflected-credential error and never escapes (a returned
	// config would be printed and persisted by the caller).
	assertReflectedTicketRejected := func(t *testing.T, cfg Config, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected reflected-ticket rejection")
		}
		if !strings.Contains(err.Error(), "reflected credential material") {
			t.Fatalf("expected fixed reflected-credential error, got %q", err.Error())
		}
		assertNoTicketLeak(t, err, hostileTicket)
		if cfg.ServerURL != "" || cfg.ApplicationID != "" || cfg.SubjectID != "" || len(cfg.Tools) != 0 || cfg.ExpiresAt != "" {
			t.Fatalf("config escaped despite reflected credential: %#v", cfg)
		}
	}

	for _, tc := range []struct {
		name   string
		mutate func(cfg map[string]any, ticket string)
	}{
		{
			name: "serverUrl",
			mutate: func(cfg map[string]any, ticket string) {
				cfg["serverUrl"] = "https://" + ticket + ".example.com/"
			},
		},
		{
			name: "applicationId",
			mutate: func(cfg map[string]any, ticket string) {
				cfg["applicationId"] = ticket
			},
		},
		{
			name: "subjectId",
			mutate: func(cfg map[string]any, ticket string) {
				cfg["subjectId"] = ticket
			},
		},
		{
			name: "tools",
			mutate: func(cfg map[string]any, ticket string) {
				cfg["tools"] = []string{"Codex", ticket}
			},
		},
		{
			name: "expiresAt",
			mutate: func(cfg map[string]any, ticket string) {
				cfg["expiresAt"] = ticket
			},
		},
		{
			name: "uppercase_hex_ticket",
			mutate: func(cfg map[string]any, ticket string) {
				cfg["applicationId"] = strings.ToUpper(ticket)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := serve(t, tc.mutate)
			defer server.Close()
			cfg, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
			assertReflectedTicketRejected(t, cfg, err)
		})
	}

	t.Run("unicode_escaped_ticket", func(t *testing.T) {
		// The JSON encodes every ticket character as a \uXXXX escape; the
		// gate must catch the reflection on the decoded value.
		server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
			var escaped strings.Builder
			for _, c := range ticket {
				_, _ = fmt.Fprintf(&escaped, `\u%04x`, c)
			}
			body := `{"schemaVersion":1,"serverUrl":"http://localhost:8080","applicationId":"app-1","subjectId":"sub-1","tools":["Codex"],"days":30,"expiresAt":"` + escaped.String() + `"}`
			_, _ = w.Write([]byte(body))
		})
		defer server.Close()
		cfg, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
		assertReflectedTicketRejected(t, cfg, err)
	})
}

func TestParseAndValidateConnectURLNeverEchoesUserSecrets(t *testing.T) {
	// A pasted connect URL can carry secrets outside the ticket fragment
	// (userinfo passwords, secret paths, secret-bearing schemes). The ticket
	// fragment is cut before parsing, but url.Parse errors and the old
	// scheme message quoted the raw URL/scheme verbatim — the failures must
	// report fixed categories instead.
	for _, tc := range []struct {
		name    string
		rawURL  string
		markers []string
	}{
		{
			name:    "unparseable_url_with_embedded_secret",
			rawURL:  "https://example.com/%zzSecretPath123#" + hostileTicket,
			markers: []string{"SecretPath123"},
		},
		{
			name:    "unparseable_userinfo_password",
			rawURL:  "https://user:PassWord%zz9@example.com/#" + hostileTicket,
			markers: []string{"PassWord"},
		},
		{
			name:    "secret_bearing_scheme",
			rawURL:  "SecretScheme9://example.com#" + hostileTicket,
			markers: []string{"SecretScheme9"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseAndValidateConnectURL(tc.rawURL)
			if err == nil {
				t.Fatal("expected connect URL rejection")
			}
			for _, text := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Errorf("connect: %w", err).Error()} {
				for _, marker := range append(tc.markers, hostileTicket) {
					if strings.Contains(text, marker) {
						t.Fatalf("user secret echoed in error: %q", text)
					}
				}
			}
		})
	}
}

// assertNoTicketLeakAnyCase renders err the ways a CLI surfaces errors and
// fails if the connect ticket appears in any rendering in ANY case variant
// (hex tickets are case-insensitive, so an uppercase reflection must be
// caught too).
func assertNoTicketLeakAnyCase(t *testing.T, err error, ticket string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	needle := strings.ToLower(ticket)
	for _, text := range []string{
		err.Error(),
		fmt.Sprint(err),
		fmt.Sprintf("%v", err),
		fmt.Errorf("connect: %w", err).Error(),
		fmt.Errorf("connect: %v", err).Error(),
	} {
		if strings.Contains(strings.ToLower(text), needle) {
			t.Fatalf("ticket (any case) leaked into error text: %q", text)
		}
	}
}

func TestFetchConnectConfigRedirectNeverLeaksCaseVariantTicket(t *testing.T) {
	now := time.Now()
	var targetHits int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&targetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
				// net/http copies the raw Location into the *url.Error it
				// returns for the refused redirect; the malicious variant
				// carries the ticket in UPPERCASE, which the old
				// case-sensitive redaction missed.
				w.Header().Set("Location", target.URL+"/leak?ticket="+strings.ToUpper(ticket))
				w.WriteHeader(status)
			})
			defer server.Close()
			_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
			if err == nil {
				t.Fatal("expected redirect rejection")
			}
			if err.Error() != "connect failed: redirects are not allowed" {
				t.Fatalf("expected fixed redirect message, got %q", err.Error())
			}
			assertNoTicketLeakAnyCase(t, err, hostileTicket)
			if hits := atomic.LoadInt64(&targetHits); hits != 0 {
				t.Fatalf("redirect target received %d requests", hits)
			}
			if !errors.Is(err, errConnectRedirect) {
				t.Fatal("expected redirect sentinel reachable via errors.Is")
			}
		})
	}
}

func TestFetchConnectConfigMalformedLocationNeverLeaksCaseVariantTicket(t *testing.T) {
	now := time.Now()
	var targetHits int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&targetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
		// A malformed Location fails to parse inside net/http BEFORE the
		// CheckRedirect hook runs, and the parse error quotes the raw
		// header verbatim.
		w.Header().Set("Location", target.URL+"/%zz"+strings.ToUpper(ticket))
		w.WriteHeader(http.StatusFound)
	})
	defer server.Close()
	_, err := fetchConnectConfig(context.Background(), server.Client(), server.URL, hostileTicket, now)
	if err == nil {
		t.Fatal("expected failure")
	}
	if err.Error() != "connect request failed" {
		t.Fatalf("expected fixed generic message, got %q", err.Error())
	}
	assertNoTicketLeakAnyCase(t, err, hostileTicket)
	if hits := atomic.LoadInt64(&targetHits); hits != 0 {
		t.Fatalf("redirect target received %d requests", hits)
	}
}

func TestFetchConnectConfigPreservesCancellationSemantics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server := hostileConfigServer(t, func(w http.ResponseWriter, ticket string) {
		cfg := hostileConfigBody(nil)
		_ = json.NewEncoder(w).Encode(cfg)
	})
	defer server.Close()
	_, err := fetchConnectConfig(ctx, server.Client(), server.URL, hostileTicket, time.Now())
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled reachable via errors.Is, got %v", err)
	}
	if err.Error() != "connect request failed" {
		t.Fatalf("expected fixed message, got %q", err.Error())
	}
	assertNoTicketLeakAnyCase(t, err, hostileTicket)
}

func TestSanitizeErrorSafetyAndSemantics(t *testing.T) {
	t.Run("unvetted_text_gets_fixed_message", func(t *testing.T) {
		cause := fmt.Errorf("connection to %s failed: secret is %s and %s",
			"https://example.com/x", hostileTicket, strings.ToUpper(hostileTicket))
		sanitized := sanitizeError(cause, hostileTicket)
		if sanitized.Error() != unvettedErrorMessage {
			t.Fatalf("expected fixed unvetted message, got %q", sanitized.Error())
		}
		assertNoTicketLeakAnyCase(t, sanitized, hostileTicket)
		if !errors.Is(sanitized, cause) {
			t.Fatal("expected cause reachable via errors.Is")
		}
	})

	t.Run("bind_error_message_passes_through", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": "unauthorized", "message": "no"},
			})
		}))
		defer server.Close()
		_, bindErr := bind.Run(context.Background(), statedir.New(t.TempDir()), bind.Options{
			ServerURL:         server.URL,
			Ticket:            "ticket-bind-err-123",
			ExternalSubjectID: "user-1",
		})
		if bindErr == nil {
			t.Fatal("expected bind failure")
		}
		sanitized := sanitizeError(bindErr, "ticket-bind-err-123")
		if sanitized.Error() != bindErr.Error() {
			t.Fatalf("expected the fixed bind message preserved, got %q", sanitized.Error())
		}
		if !errors.Is(sanitized, bindErr) {
			t.Fatal("expected cause reachable via errors.Is")
		}
		var be *bind.Error
		if !errors.As(sanitized, &be) {
			t.Fatal("expected *bind.Error reachable via errors.As")
		}
	})
}
