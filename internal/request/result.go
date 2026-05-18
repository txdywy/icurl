package request

import (
	"io"
	"net/http"
	"time"
)

type Timing struct {
	Total time.Duration
}

type Redirect struct {
	From       string `json:"from"`
	To         string `json:"to"`
	StatusCode int    `json:"status_code"`
}

type Result struct {
	URL             string
	StatusCode      int
	Protocol        string
	ResponseHeaders http.Header
	Body            io.ReadCloser
	Timing          Timing
	Redirects       []Redirect
}