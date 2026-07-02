package adapter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// udsBaseURL is the synthetic authority used for requests over a Unix domain
// socket; the custom DialContext ignores the address entirely.
const udsBaseURL = "http://talon-scanner"

// ParseEndpoint splits a configured scanner endpoint into the base URL
// requests are built against and, for unix:// endpoints, the socket path.
func ParseEndpoint(endpoint string) (baseURL, socketPath string, err error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("invalid scanner endpoint: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return "", "", fmt.Errorf("scanner endpoint %q has no host", endpoint)
		}
		return strings.TrimRight(endpoint, "/"), "", nil
	case "unix":
		// With the canonical triple-slash form the socket path lands in
		// u.Path; with a double slash the first segment lands in u.Host, so
		// rejoin it to tolerate both spellings.
		path := u.Path
		if u.Host != "" {
			path = "/" + u.Host + u.Path
		}
		if path == "" || path == "/" {
			return "", "", fmt.Errorf("scanner endpoint %q has no socket path", endpoint)
		}
		return udsBaseURL, path, nil
	default:
		return "", "", fmt.Errorf("scanner endpoint scheme %q is unsupported (use http, https, or unix)", u.Scheme)
	}
}

// newHTTPClient builds the adapter's HTTP client. For unix sockets every
// connection dials the socket path regardless of the request URL. Deadlines
// come from the per-call context, not the client, so health probes and scans
// can use different budgets. A caller-provided base transport (e.g. the
// air-gap egress guard) wraps the dialing transport.
func newHTTPClient(socketPath string, base http.RoundTripper) *http.Client {
	if socketPath != "" {
		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		}
	}
	if base != nil {
		return &http.Client{Transport: base}
	}
	return &http.Client{}
}
