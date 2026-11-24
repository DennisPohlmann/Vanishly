package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The global flags work before and after the command.
func TestGlobalFlagsAfterCommand(t *testing.T) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path+" "+r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	t.Setenv("VANISHLY_URL", "")
	for _, args := range [][]string{
		{"--url", srv.URL, "config"},
		{"config", "--url", srv.URL},
		{"me", "--url", srv.URL, "--token", "vnly_x", "--json"},
	} {
		if err := run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	want := []string{"/api/v1/config ", "/api/v1/config ", "/api/v1/me Bearer vnly_x"}
	if len(hits) != len(want) {
		t.Fatalf("hits %v", hits)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Errorf("hit %d: %q, want %q", i, hits[i], want[i])
		}
	}
	if err := run([]string{"config", "extra", "--url", srv.URL}); err != errUsage {
		t.Errorf("extra argument: %v", err)
	}
}
