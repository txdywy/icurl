package request

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Protocol string

const (
	ProtocolAuto      Protocol = "auto"
	ProtocolHTTP11    Protocol = "http1.1"
	ProtocolHTTP2     Protocol = "http2"
	ProtocolHTTP3     Protocol = "http3"
	ProtocolHTTP3Only Protocol = "http3-only"
)

type Config struct {
	URL            string
	Host           string // explicit host to use for SNI/Host header
	Method         string
	Headers        http.Header
	Body           string
	Head           bool
	IncludeHeaders bool
	FollowRedirect bool
	ConnectTimeout time.Duration
	MaxTime        time.Duration
	Protocol       Protocol
	Diagnose       bool
	JSON           bool
}

func (c Config) EffectiveMethod() string {
	if c.Head {
		return http.MethodHead
	}
	if c.Method != "" {
		return strings.ToUpper(c.Method)
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
