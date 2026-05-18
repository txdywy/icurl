package request

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type ProtocolMode string

const (
	ProtocolAuto      ProtocolMode = "auto"
	ProtocolHTTP11    ProtocolMode = "http1.1"
	ProtocolHTTP2     ProtocolMode = "http2"
	ProtocolHTTP3     ProtocolMode = "http3"
	ProtocolHTTP3Only ProtocolMode = "http3-only"
)

type Config struct {
	URL            string
	Method         string
	Headers        http.Header
	Body           string
	Head           bool
	IncludeHeaders bool
	FollowRedirect bool
	ConnectTimeout time.Duration
	MaxTime        time.Duration
	Protocol       ProtocolMode
	Diagnose       bool
	JSON           bool
}

func (c Config) EffectiveMethod() string {
	if c.Method != "" {
		return strings.ToUpper(c.Method)
	}
	if c.Head {
		return http.MethodHead
	}
	if c.Body != "" {
		return http.MethodPost
	}
	return http.MethodGet
}

type HeaderList struct {
	Values http.Header
}

func (h *HeaderList) String() string {
	if h == nil || len(h.Values) == 0 {
		return ""
	}

	keys := make([]string, 0, len(h.Values))
	for key := range h.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", key, strings.Join(h.Values[key], ", ")))
	}
	return strings.Join(parts, "; ")
}

func (h *HeaderList) Set(value string) error {
	name, raw, ok := strings.Cut(value, ":")
	if !ok {
		return fmt.Errorf("header must be in Name: value form")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("header name cannot be empty")
	}
	if h.Values == nil {
		h.Values = make(http.Header)
	}
	h.Values.Add(name, strings.TrimSpace(raw))
	return nil
}
