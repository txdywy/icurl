package request

import "testing"

func TestHeaderListSetParsesNameAndValue(t *testing.T) {
	var headers HeaderList
	if err := headers.Set("Accept: application/json"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if got := headers.Values.Get("Accept"); got != "application/json" {
		t.Fatalf("expected Accept header, got %q", got)
	}
}

func TestHeaderListSetRejectsMissingColon(t *testing.T) {
	var headers HeaderList
	if err := headers.Set("Accept application/json"); err == nil {
		t.Fatal("expected error for header without colon")
	}
}

func TestHeaderListSetRejectsEmptyName(t *testing.T) {
	var headers HeaderList
	if err := headers.Set(": value"); err == nil {
		t.Fatal("expected error for empty header name")
	}
}

func TestConfigMethodDefaultsToHeadWhenHeadIsTrue(t *testing.T) {
	cfg := Config{Head: true}
	if got := cfg.EffectiveMethod(); got != "HEAD" {
		t.Fatalf("expected HEAD, got %q", got)
	}
}

func TestConfigMethodDefaultsToPostWhenBodyExists(t *testing.T) {
	cfg := Config{Body: "hello"}
	if got := cfg.EffectiveMethod(); got != "POST" {
		t.Fatalf("expected POST, got %q", got)
	}
}

func TestConfigMethodDefaultsToGet(t *testing.T) {
	cfg := Config{}
	if got := cfg.EffectiveMethod(); got != "GET" {
		t.Fatalf("expected GET, got %q", got)
	}
}
