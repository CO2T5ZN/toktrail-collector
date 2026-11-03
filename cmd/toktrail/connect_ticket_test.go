package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"toktrail-collector/internal/bind"
	"toktrail-collector/internal/local/statedir"
)

func TestConnectSupersededTicketGuidance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"ticket_superseded","message":"untrusted server text"}}`)
	}))
	defer server.Close()
	_, err := bind.Run(context.Background(), statedir.New(t.TempDir()), bind.Options{
		ServerURL: server.URL, Ticket: "ticket-secret", ExternalSubjectID: "user-1",
	})
	if err == nil {
		t.Fatal("expected rejected ticket")
	}
	got := runFailureDisplayText(fmt.Errorf("binding failed: %w", err), "generic failure")
	if !strings.Contains(got, "generate a new command") || strings.Contains(got, "ticket-secret") || strings.Contains(got, "untrusted") {
		t.Fatalf("unexpected safe guidance: %q", got)
	}
}
