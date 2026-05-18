package report

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"icurl/internal/diagnose"
	"icurl/internal/request"
)

type requestJSON struct {
	URL        string             `json:"url"`
	StatusCode int                `json:"status_code"`
	Protocol   string             `json:"protocol"`
	Headers    http.Header        `json:"headers"`
	BodyBase64 string             `json:"body_base64"`
	Redirects  []request.Redirect `json:"redirects"`
}

func WriteRequestJSON(w io.Writer, result request.Result) error {
	var bodyBytes []byte
	if result.Body != nil {
		bodyBytes, _ = io.ReadAll(result.Body)
		_ = result.Body.Close()
	}
	payload := requestJSON{
		URL:        result.URL,
		StatusCode: result.StatusCode,
		Protocol:   result.Protocol,
		Headers:    result.ResponseHeaders,
		BodyBase64: base64.StdEncoding.EncodeToString(bodyBytes),
		Redirects:  result.Redirects,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func WriteDiagnoseJSON(w io.Writer, result diagnose.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
