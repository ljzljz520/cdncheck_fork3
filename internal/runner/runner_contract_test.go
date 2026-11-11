package runner

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

// brokenResolver refuses every DNS query immediately, so domain resolution
// fails deterministically without depending on external networks.
var brokenResolver = goflags.StringSlice{"127.0.0.1:1"}

// TestRunnerExcludeSkipsUndeterminedDomain verifies the core exclusion
// contract: a domain whose resolution fails is reported as undetermined
// through the callback with query diagnostics, but never written as an
// exclusion target, while a confirmed non-matching IP is still emitted.
func TestRunnerExcludeSkipsUndeterminedDomain(t *testing.T) {
	inputs := []string{"192.0.2.1", "unresolvable-dns-failure.example"}

	var mu sync.Mutex
	callbackResults := map[string]Output{}
	var written bytes.Buffer

	runner := NewRunner(&Options{
		Inputs:     inputs,
		Threads:    2,
		Exclude:    true,
		MaxRetries: 1,
		Resolvers:  brokenResolver,
		OnResult: func(result Output) {
			mu.Lock()
			callbackResults[result.Input] = result
			mu.Unlock()
		},
	})
	require.NoError(t, runner.SetWriter(&written))
	require.NoError(t, runner.Run())

	// Both inputs reach the callback, each carrying the three-state status.
	require.Len(t, callbackResults, len(inputs))

	ipResult := callbackResults["192.0.2.1"]
	require.Equal(t, cdncheck.DomainStatusMissed, ipResult.Status)
	require.True(t, ipResult.AddressQuery == nil, "raw IP inputs do not carry DNS stage diagnostics")

	domainResult := callbackResults["unresolvable-dns-failure.example"]
	require.Equal(t, cdncheck.DomainStatusUndetermined, domainResult.Status)
	require.NotEmpty(t, domainResult.Reasons)
	require.NotNil(t, domainResult.AddressQuery)
	require.Equal(t, cdncheck.QueryStatusFailed, domainResult.AddressQuery.Status)
	require.NotEmpty(t, domainResult.AddressQuery.Reason)
	require.NotNil(t, domainResult.CNAMEQuery)
	require.Equal(t, cdncheck.QueryStatusFailed, domainResult.CNAMEQuery.Status)

	// Only the confirmed miss is written; the undetermined domain is absent.
	outputLines := strings.Split(strings.TrimSpace(written.String()), "\n")
	require.Equal(t, []string{"192.0.2.1"}, outputLines)
	require.NotContains(t, written.String(), "unresolvable-dns-failure.example")
}

// TestRunnerMatchedIPKeepsDetectionOutput verifies that normal matched IP
// results remain compatible and carry the new status contract in JSON output.
func TestRunnerMatchedIPKeepsDetectionOutput(t *testing.T) {
	var written bytes.Buffer
	seen := map[string]Output{}

	runner := NewRunner(&Options{
		Inputs:     []string{"173.245.48.12"},
		Threads:    1,
		Json:       true,
		MaxRetries: 1,
		OnResult: func(result Output) {
			seen[result.Input] = result
		},
	})
	require.NoError(t, runner.SetWriter(&written))
	require.NoError(t, runner.Run())

	result, ok := seen["173.245.48.12"]
	require.True(t, ok)
	require.Equal(t, cdncheck.DomainStatusMatched, result.Status)
	require.True(t, result.Waf)
	require.Equal(t, "cloudflare", result.WafName)

	jsonLine := written.String()
	require.Contains(t, jsonLine, `"status":"matched"`)
	require.Contains(t, jsonLine, `"waf":true`)
	require.Contains(t, jsonLine, `"waf_name":"cloudflare"`)
}

// TestRunnerNonExcludeModeSuppressesMissedAndUndetermined verifies that
// detection mode keeps its historical behavior of emitting matches only,
// while undetermined domains are still observable through the callback but
// never through the writer.
func TestRunnerNonExcludeModeSuppressesMissedAndUndetermined(t *testing.T) {
	var written bytes.Buffer
	statuses := map[string]string{}
	var mu sync.Mutex

	runner := NewRunner(&Options{
		Inputs:     []string{"192.0.2.1", "unresolvable-dns-failure.example"},
		Threads:    1,
		MaxRetries: 1,
		Resolvers:  brokenResolver,
		OnResult: func(result Output) {
			mu.Lock()
			statuses[result.Input] = result.Status
			mu.Unlock()
		},
	})
	require.NoError(t, runner.SetWriter(&written))
	require.NoError(t, runner.Run())

	// Undetermined diagnostics always reach the callback; historical
	// non-exclude deliveries (matches only) are otherwise unchanged.
	require.Equal(t, cdncheck.DomainStatusUndetermined, statuses["unresolvable-dns-failure.example"])
	_, missedDelivered := statuses["192.0.2.1"]
	require.False(t, missedDelivered, "missed inputs must not be delivered in detection mode")
	require.Empty(t, strings.TrimSpace(written.String()), "non-exclude mode must not write misses or undetermined inputs")
}
