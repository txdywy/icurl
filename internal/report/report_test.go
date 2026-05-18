package report

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"icurl/internal/diagnose"
	"icurl/internal/evidence"
	"icurl/internal/request"
)

func TestWriteRequestHumanIncludesHeadersWhenRequested(t *testing.T) {
	var out bytes.Buffer
	result := request.Result{
		StatusCode: 200,
		Protocol:   "HTTP/1.1",
		ResponseHeaders: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("hello"))),
	}

	err := WriteRequestHuman(&out, result, RequestHumanOptions{IncludeHeaders: true})

	if err != nil {
		t.Fatalf("WriteRequestHuman returned error: %v", err)
	}
	want := "HTTP/1.1 200\nContent-Type: text/plain\n\nhello"
	if out.String() != want {
		t.Fatalf("unexpected output\nwant: %q\n got: %q", want, out.String())
	}
}

func TestWriteRequestJSONIsStable(t *testing.T) {
	var out bytes.Buffer
	result := request.Result{
		StatusCode: 204,
		Protocol:   "HTTP/2.0",
	}

	err := WriteRequestJSON(&out, result)

	if err != nil {
		t.Fatalf("WriteRequestJSON returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if got["status_code"] != float64(204) {
		t.Fatalf("unexpected status_code %#v", got["status_code"])
	}
	if got["protocol"] != "HTTP/2.0" {
		t.Fatalf("unexpected protocol %#v", got["protocol"])
	}
}

func TestWriteDiagnoseHumanIncludesAssessmentAndLayers(t *testing.T) {
	var out bytes.Buffer
	result := diagnose.Result{
		Target: "https://example.com",
		ProbeResults: []evidence.ProbeResult{
			{Layer: evidence.LayerDNS, Result: evidence.ResultOK},
			{Layer: evidence.LayerTLS, Result: evidence.ResultFailed, ErrorMessage: "reset before certificate"},
		},
		Assessment: evidence.Assessment{
			Level:    evidence.AssessmentSuspiciousHigh,
			Category: "TLS_SNI_INTERRUPTION_PATTERN",
			Summary:  "TLS interrupted",
		},
	}

	err := WriteDiagnoseHuman(&out, result)

	if err != nil {
		t.Fatalf("WriteDiagnoseHuman returned error: %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "Layer summary") {
		t.Fatalf("output missing layer summary: %q", output)
	}
	if !strings.Contains(output, "TLS_SNI_INTERRUPTION_PATTERN") {
		t.Fatalf("output missing category: %q", output)
	}
}

func TestWriteDiagnoseJSONIncludesAssessment(t *testing.T) {
	var out bytes.Buffer
	result := diagnose.Result{
		Assessment: evidence.Assessment{
			Level:    evidence.AssessmentUnknown,
			Category: "INSUFFICIENT_EVIDENCE",
		},
	}

	err := WriteDiagnoseJSON(&out, result)

	if err != nil {
		t.Fatalf("WriteDiagnoseJSON returned error: %v", err)
	}
	if !strings.Contains(out.String(), "INSUFFICIENT_EVIDENCE") {
		t.Fatalf("output missing assessment category: %q", out.String())
	}
}
