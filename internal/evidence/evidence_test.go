package evidence

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProbeResultJSONFields(t *testing.T) {
	started := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	finished := started.Add(150 * time.Millisecond)
	probe := ProbeResult{
		ProbeName:     "tls",
		Layer:         LayerTLS,
		Target:        "example.com:443",
		RemoteAddress: "93.184.216.34:443",
		LocalAddress:  "192.0.2.10:51000",
		StartedAt:     &started,
		FinishedAt:    &finished,
		DurationNS:    150000000,
		Result:        ResultFailed,
		ErrorKind:     ErrorReset,
		ErrorMessage:  "connection reset by peer",
		Observations:  []string{"tcp connection succeeded", "reset during TLS handshake"},
		Confidence:    ConfidenceObserved,
	}

	data, err := json.Marshal(probe)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}

	want := map[string]any{
		"probe_name":     "tls",
		"layer":          "TLS",
		"target":         "example.com:443",
		"remote_address": "93.184.216.34:443",
		"local_address":  "192.0.2.10:51000",
		"duration_ns":    float64(150000000),
		"result":         "FAILED",
		"error_kind":     "RESET",
		"error_message":  "connection reset by peer",
		"confidence":     "observed",
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("unexpected %s: want %#v got %#v", key, value, got[key])
		}
	}
	if got["started_at"] != "2026-05-18T12:00:00Z" {
		t.Fatalf("unexpected started_at %#v", got["started_at"])
	}
	if got["finished_at"] != "2026-05-18T12:00:00.15Z" {
		t.Fatalf("unexpected finished_at %#v", got["finished_at"])
	}
	observations, ok := got["observations"].([]any)
	if !ok || len(observations) != 2 || observations[0] != "tcp connection succeeded" || observations[1] != "reset during TLS handshake" {
		t.Fatalf("unexpected observations %#v", got["observations"])
	}
}
