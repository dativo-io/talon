// Package scanner builds the process-wide PII scanner engine from operator
// configuration: the built-in regex scanner by default, or an external
// adapter (Presidio sidecar, custom HTTP engine, local LLM) when configured.
// It owns startup validation: endpoint locality under air-gap sovereignty and
// the eager health probe that refuses to start against a dead engine.
package scanner

import (
	"fmt"
	"net"
	"net/url"

	"github.com/rs/zerolog/log"
)

// ValidateEndpointLocality enforces sovereignty rules on a scanner endpoint.
// In air-gap mode only provably local destinations are accepted: Unix domain
// sockets, loopback, RFC1918/ULA/link-local addresses, and the literal
// "localhost". DNS hostnames are rejected — they cannot be proven local at
// startup and could re-resolve to a public address later. Outside air-gap
// mode any endpoint is accepted, with a warning for non-local ones (the
// adapter protocol carries no authentication; isolation is the operator's
// responsibility).
func ValidateEndpointLocality(endpoint string, airGap bool) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid scanner endpoint: %w", err)
	}
	if u.Scheme == "unix" {
		return nil
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("scanner endpoint %q has no host", endpoint)
	}

	local := isLocalHost(host)
	if airGap && !local {
		return fmt.Errorf(
			"scanner endpoint %q is not provably local; air_gap deployments accept only unix:// sockets, loopback, and private (RFC1918/ULA/link-local) addresses",
			endpoint)
	}
	if !local {
		log.Warn().Str("endpoint_host", host).Msg(
			"external scanner endpoint is not local; the adapter protocol has no authentication — ensure network isolation")
	}
	return nil
}

// isLocalHost reports whether host is "localhost" or a loopback/private/
// link-local IP literal. DNS names other than localhost return false.
func isLocalHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
