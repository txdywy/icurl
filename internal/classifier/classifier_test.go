package classifier

import (
	"reflect"
	"testing"

	"icurl/internal/evidence"
)

func TestClassifyDNSInterference(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{
			ProbeName:    "dns",
			Layer:        evidence.LayerDNS,
			Result:       evidence.ResultFailed,
			ErrorKind:    evidence.ErrorSuspiciousDNS,
			ErrorMessage: "unexpected private address answer",
			Observations: []string{"answer differs from resolver baseline"},
		},
	})

	assertAssessment(t, assessment, evidence.AssessmentSuspiciousHigh, "DNS_INTERFERENCE_PATTERN")
	assertReasons(t, assessment.Reasons, []string{
		"dns: unexpected private address answer",
		"dns: answer differs from resolver baseline",
	})
}

func TestClassifyTLSInterruption(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "tls", Layer: evidence.LayerTLS, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorReset, ErrorMessage: "connection reset during handshake"},
	})

	assertAssessment(t, assessment, evidence.AssessmentSuspiciousHigh, "TLS_SNI_INTERRUPTION_PATTERN")
}

func TestClassifyTLSCertificateError(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "tls", Layer: evidence.LayerTLS, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorCertificate, ErrorMessage: "certificate expired"},
	})

	assertAssessment(t, assessment, evidence.AssessmentFail, "TLS_CERTIFICATE_ERROR")
}

func TestClassifyQUICBlockage(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "tls", Layer: evidence.LayerTLS, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "quic", Layer: evidence.LayerQUIC, Result: evidence.ResultTimeout, ErrorKind: evidence.ErrorTimeout, ErrorMessage: "QUIC handshake timed out"},
	})

	assertAssessment(t, assessment, evidence.AssessmentSuspiciousMedium, "UDP_QUIC_BLOCKAGE_PATTERN")
}

func TestClassifyHTTPOriginFailure(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "dns", Layer: evidence.LayerDNS, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "tls", Layer: evidence.LayerTLS, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "http", Layer: evidence.LayerHTTP, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorProtocol, ErrorMessage: "origin returned malformed response"},
	})

	assertAssessment(t, assessment, evidence.AssessmentFail, "HTTP_ORIGIN_FAILURE")
}

func TestClassifyAllPass(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "dns", Layer: evidence.LayerDNS, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone},
		{ProbeName: "quic", Layer: evidence.LayerQUIC, Result: evidence.ResultSkipped, ErrorKind: evidence.ErrorNone},
	})

	assertAssessment(t, assessment, evidence.AssessmentPass, "PASS")
}

func TestClassifyUnknown(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorRefused, ErrorMessage: "connection refused"},
	})

	assertAssessment(t, assessment, evidence.AssessmentUnknown, "INSUFFICIENT_EVIDENCE")
}

func assertAssessment(t *testing.T, assessment evidence.Assessment, level evidence.AssessmentLevel, category string) {
	t.Helper()
	if assessment.Level != level {
		t.Fatalf("unexpected level: want %s got %s", level, assessment.Level)
	}
	if assessment.Category != category {
		t.Fatalf("unexpected category: want %s got %s", category, assessment.Category)
	}
	if assessment.Summary == "" {
		t.Fatalf("summary should not be empty")
	}
}

func assertReasons(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reasons: want %#v got %#v", want, got)
	}
}
