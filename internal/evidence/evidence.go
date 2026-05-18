package evidence

import "time"

type Layer string

const (
	LayerDNS   Layer = "DNS"
	LayerTCP   Layer = "TCP"
	LayerTLS   Layer = "TLS"
	LayerHTTP  Layer = "HTTP"
	LayerUDP   Layer = "UDP"
	LayerQUIC  Layer = "QUIC"
	LayerLOCAL Layer = "LOCAL"
)

type Result string

const (
	ResultOK      Result = "OK"
	ResultFailed  Result = "FAILED"
	ResultTimeout Result = "TIMEOUT"
	ResultSkipped Result = "SKIPPED"
)

type ErrorKind string

const (
	ErrorNone          ErrorKind = "NONE"
	ErrorTimeout       ErrorKind = "TIMEOUT"
	ErrorRefused       ErrorKind = "REFUSED"
	ErrorReset         ErrorKind = "RESET"
	ErrorUnreachable   ErrorKind = "UNREACHABLE"
	ErrorCertificate   ErrorKind = "CERTIFICATE"
	ErrorProtocol      ErrorKind = "PROTOCOL"
	ErrorSuspiciousDNS ErrorKind = "SUSPICIOUS_DNS"
	ErrorPermission    ErrorKind = "PERMISSION"
	ErrorUnknown       ErrorKind = "UNKNOWN"
)

type Confidence string

const (
	ConfidenceObserved Confidence = "observed"
	ConfidenceInferred Confidence = "inferred"
)

type AssessmentLevel string

const (
	AssessmentPass             AssessmentLevel = "PASS"
	AssessmentFail             AssessmentLevel = "FAIL"
	AssessmentSuspiciousLow    AssessmentLevel = "SUSPICIOUS_LOW"
	AssessmentSuspiciousMedium AssessmentLevel = "SUSPICIOUS_MEDIUM"
	AssessmentSuspiciousHigh   AssessmentLevel = "SUSPICIOUS_HIGH"
	AssessmentUnknown          AssessmentLevel = "UNKNOWN"
)

type ProbeResult struct {
	ProbeName     string     `json:"probe_name"`
	Layer         Layer      `json:"layer"`
	Target        string     `json:"target"`
	RemoteAddress string     `json:"remote_address,omitempty"`
	LocalAddress  string     `json:"local_address,omitempty"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	DurationNS    int64      `json:"duration_ns"`
	Result        Result     `json:"result"`
	ErrorKind     ErrorKind  `json:"error_kind"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	Observations  []string   `json:"observations,omitempty"`
	Confidence    Confidence `json:"confidence"`
}

type Assessment struct {
	Level     AssessmentLevel `json:"level"`
	Category  string          `json:"category"`
	Summary   string          `json:"summary"`
	Reasons   []string        `json:"reasons"`
	NextSteps []string        `json:"next_steps"`
}
