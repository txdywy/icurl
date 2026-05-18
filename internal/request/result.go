package request

import (
	"net/http"
	"time"
)

type Timing struct {
	Total time.Duration
}

type Redirect struct {
	URL        string
	StatusCode int
}

type Result struct {
	URL             string
	StatusCode      int
	Protocol        string
	ResponseHeaders http.Header
	Body            []byte
	Timing          Timing
	Redirects       []Redirect
}
