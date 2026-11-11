package cdncheck

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
)

const (
	// cloudflare ranges shipped in the generated data
	cloudflareIPv4 = "173.245.48.12"
	cloudflareIPv6 = "2400:cb00::1"
	// TEST-NET-1 documentation range, never present in provider data
	documentationIP = "192.0.2.1"
)

func noerrorResponse(a, aaaa, cname []string) *retryabledns.DNSData {
	return &retryabledns.DNSData{
		Host:          "example.com",
		StatusCode:    "NOERROR",
		StatusCodeRaw: 0,
		A:             a,
		AAAA:          aaaa,
		CNAME:         cname,
	}
}

func nxdomainResponse() *retryabledns.DNSData {
	return &retryabledns.DNSData{
		Host:          "example.com",
		StatusCode:    "NXDOMAIN",
		StatusCodeRaw: 3,
	}
}

// TestEvaluateDomainResultStates exercises the three-state contract across
// timeout, resolution failure, no-address response and partial-query
// combinations without any network dependency.
func TestEvaluateDomainResultStates(t *testing.T) {
	client := New()

	tests := []struct {
		name             string
		addrData         *retryabledns.DNSData
		addrErr          error
		cnameData        *retryabledns.DNSData
		cnameErr         error
		cnameSkipped     bool
		wantStatus       string
		wantMatched      bool
		wantProvider     string
		wantItemType     string
		wantUsableAddr   bool
		wantAddrStatus   string
		wantCnameStatus  string
		wantReasonSubstr string
	}{
		{
			name:            "matched via A record, CNAME fallback skipped",
			addrData:        noerrorResponse([]string{cloudflareIPv4}, nil, nil),
			cnameSkipped:    true,
			wantStatus:      DomainStatusMatched,
			wantMatched:     true,
			wantProvider:    "cloudflare",
			wantItemType:    "waf",
			wantUsableAddr:  true,
			wantAddrStatus:  QueryStatusCompleted,
			wantCnameStatus: QueryStatusSkipped,
		},
		{
			name: "partial resolution error with positive AAAA evidence stays matched",
			addrData: &retryabledns.DNSData{
				StatusCode:    "NOERROR",
				StatusCodeRaw: 0,
				AAAA:          []string{cloudflareIPv6},
			},
			addrErr:          retryabledns.ErrRetriesExceeded,
			cnameSkipped:     true,
			wantStatus:       DomainStatusMatched,
			wantMatched:      true,
			wantProvider:     "cloudflare",
			wantItemType:     "waf",
			wantUsableAddr:   true,
			wantAddrStatus:   QueryStatusCompleted,
			wantCnameStatus:  QueryStatusSkipped,
			wantReasonSubstr: "partial resolution error",
		},
		{
			name: "CNAME suffix evidence without any address still matches",
			addrData: &retryabledns.DNSData{
				StatusCode:    "NOERROR",
				StatusCodeRaw: 0,
				CNAME:         []string{"test.cloudfront.net"},
			},
			cnameSkipped:    true,
			wantStatus:      DomainStatusMatched,
			wantMatched:     true,
			wantProvider:    "amazon",
			wantItemType:    "waf",
			wantUsableAddr:  false,
			wantAddrStatus:  QueryStatusFailed,
			wantCnameStatus: QueryStatusSkipped,
		},
		{
			name:            "confirmed miss with usable address and completed CNAME fallback",
			addrData:        noerrorResponse([]string{documentationIP}, nil, nil),
			cnameData:       noerrorResponse(nil, nil, nil),
			wantStatus:      DomainStatusMissed,
			wantUsableAddr:  true,
			wantAddrStatus:  QueryStatusCompleted,
			wantCnameStatus: QueryStatusCompleted,
		},
		{
			name: "partial address error but usable address, completed fallback is a miss",
			addrData: &retryabledns.DNSData{
				StatusCode:    "NOERROR",
				StatusCodeRaw: 0,
				A:             []string{documentationIP},
			},
			addrErr:          retryabledns.ErrRetriesExceeded,
			cnameData:        noerrorResponse(nil, nil, nil),
			wantStatus:       DomainStatusMissed,
			wantUsableAddr:   true,
			wantAddrStatus:   QueryStatusCompleted,
			wantCnameStatus:  QueryStatusCompleted,
			wantReasonSubstr: "partial resolution error",
		},
		{
			name:             "timeout on both stages is undetermined",
			addrErr:          retryabledns.ErrRetriesExceeded,
			cnameErr:         retryabledns.ErrRetriesExceeded,
			wantStatus:       DomainStatusUndetermined,
			wantUsableAddr:   false,
			wantAddrStatus:   QueryStatusFailed,
			wantCnameStatus:  QueryStatusFailed,
			wantReasonSubstr: "address query incomplete",
		},
		{
			name:             "NXDOMAIN without addresses is undetermined, not a miss",
			addrData:         nxdomainResponse(),
			cnameData:        nxdomainResponse(),
			wantStatus:       DomainStatusUndetermined,
			wantUsableAddr:   false,
			wantAddrStatus:   QueryStatusFailed,
			wantCnameStatus:  QueryStatusCompleted,
			wantReasonSubstr: "NXDOMAIN",
		},
		{
			name: "NOERROR response without any address record is undetermined",
			addrData: &retryabledns.DNSData{
				StatusCode:    "NOERROR",
				StatusCodeRaw: 0,
			},
			cnameData:        noerrorResponse(nil, nil, nil),
			wantStatus:       DomainStatusUndetermined,
			wantUsableAddr:   false,
			wantAddrStatus:   QueryStatusFailed,
			wantCnameStatus:  QueryStatusCompleted,
			wantReasonSubstr: "NOERROR",
		},
		{
			name:             "CNAME fallback failure after usable addresses is undetermined",
			addrData:         noerrorResponse([]string{documentationIP}, nil, nil),
			cnameErr:         retryabledns.ErrRetriesExceeded,
			wantStatus:       DomainStatusUndetermined,
			wantUsableAddr:   true,
			wantAddrStatus:   QueryStatusCompleted,
			wantCnameStatus:  QueryStatusFailed,
			wantReasonSubstr: "cname fallback incomplete",
		},
		{
			name:            "match recovered through CNAME fallback stage",
			addrData:        noerrorResponse([]string{documentationIP}, nil, nil),
			cnameData:       noerrorResponse(nil, nil, []string{"test.cloudfront.net"}),
			wantStatus:      DomainStatusMatched,
			wantMatched:     true,
			wantProvider:    "amazon",
			wantItemType:    "waf",
			wantUsableAddr:  true,
			wantAddrStatus:  QueryStatusCompleted,
			wantCnameStatus: QueryStatusCompleted,
		},
		{
			name:             "nil response without error stays undetermined",
			wantStatus:       DomainStatusUndetermined,
			wantAddrStatus:   QueryStatusFailed,
			wantCnameStatus:  QueryStatusFailed,
			wantReasonSubstr: "address query incomplete",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := client.evaluateDomainResult("example.com", tc.addrData, tc.addrErr, tc.cnameData, tc.cnameErr, tc.cnameSkipped)

			require.Equal(t, tc.wantStatus, result.Status, "unexpected status")
			require.Equal(t, tc.wantMatched, result.Matched, "unexpected matched flag")
			require.Equal(t, tc.wantProvider, result.Provider, "unexpected provider")
			require.Equal(t, tc.wantItemType, result.ItemType, "unexpected item type")
			require.Equal(t, tc.wantUsableAddr, result.HasUsableAddress(), "unexpected usable address presence")
			require.Equal(t, tc.wantAddrStatus, result.AddressQuery.Status, "unexpected address query status")
			require.Equal(t, StageAddress, result.AddressQuery.Stage)
			require.Equal(t, tc.wantCnameStatus, result.CNAMEQuery.Status, "unexpected cname query status")
			require.Equal(t, StageCNAME, result.CNAMEQuery.Stage)

			switch result.Status {
			case DomainStatusMatched:
				require.True(t, result.Matched)
				require.Empty(t, result.Reasons)
				require.NoError(t, result.Err())
			case DomainStatusMissed:
				require.False(t, result.Matched)
				require.NoError(t, result.Err())
				require.True(t, result.HasUsableAddress(), "miss requires a usable address")
			case DomainStatusUndetermined:
				require.False(t, result.Matched)
				require.Error(t, result.Err())
				require.True(t, errors.Is(result.Err(), ErrDomainUndetermined), "undetermined error must wrap ErrDomainUndetermined")
				require.NotEmpty(t, result.Reasons)
			}

			if tc.wantReasonSubstr != "" {
				allText := result.AddressQuery.Reason + " " + result.CNAMEQuery.Reason + " " + joinReasons(result.Reasons)
				require.Contains(t, allText, tc.wantReasonSubstr)
			}
		})
	}
}

func joinReasons(reasons []string) string {
	out := ""
	for _, reason := range reasons {
		out += reason + " "
	}
	return out
}

// TestLegacyDomainResultMapping verifies the historical four-value signature
// keeps its semantics on top of the new three-state contract.
func TestLegacyDomainResultMapping(t *testing.T) {
	matched := &DomainCheckResult{Status: DomainStatusMatched, Matched: true, Provider: "cloudflare", ItemType: "waf"}
	legacyMatched, provider, itemType, err := legacyDomainResult(matched)
	require.True(t, legacyMatched)
	require.Equal(t, "cloudflare", provider)
	require.Equal(t, "waf", itemType)
	require.NoError(t, err)

	missed := &DomainCheckResult{Status: DomainStatusMissed, Addresses: []string{documentationIP}}
	legacyMatched, provider, itemType, err = legacyDomainResult(missed)
	require.False(t, legacyMatched)
	require.Empty(t, provider)
	require.Empty(t, itemType)
	require.NoError(t, err, "confirmed miss must keep returning nil error")

	undetermined := &DomainCheckResult{
		Status:     DomainStatusUndetermined,
		Reasons:    []string{"address query incomplete: no usable address record in DNS response (rcode=NXDOMAIN)"},
		underlying: retryabledns.ErrRetriesExceeded,
	}
	legacyMatched, provider, itemType, err = legacyDomainResult(undetermined)
	require.False(t, legacyMatched)
	require.Empty(t, provider)
	require.Empty(t, itemType)
	require.Error(t, err, "undetermined inputs must no longer look like successful misses")
	require.True(t, errors.Is(err, ErrDomainUndetermined))
}

// TestDomainCheckResultJSON verifies diagnostics survive JSON serialization
// for the callback / JSONL contract.
func TestDomainCheckResultJSON(t *testing.T) {
	result := &DomainCheckResult{
		Input:        "example.com",
		Status:       DomainStatusUndetermined,
		IP:           "",
		Addresses:    nil,
		AddressQuery: QueryDiagnostic{Stage: StageAddress, Status: QueryStatusFailed, Reason: "boom", StatusCode: "NXDOMAIN"},
		CNAMEQuery:   QueryDiagnostic{Stage: StageCNAME, Status: QueryStatusCompleted, StatusCode: "NOERROR"},
		Reasons:      []string{"address query incomplete: boom"},
	}

	raw, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, "undetermined", decoded["status"])
	require.Equal(t, "failed", decoded["address_query"].(map[string]any)["status"])
	require.Equal(t, "boom", decoded["address_query"].(map[string]any)["reason"])
	require.Equal(t, "completed", decoded["cname_query"].(map[string]any)["status"])
}

// TestCollectAddressesOrder verifies AAAA records are reported before A
// records, matching CheckDNSResponse evaluation order.
func TestCollectAddressesOrder(t *testing.T) {
	data := &retryabledns.DNSData{
		A:    []string{documentationIP, "bad-ip"},
		AAAA: []string{cloudflareIPv6},
	}
	addresses := collectAddresses(data)
	require.Equal(t, []string{cloudflareIPv6, documentationIP}, addresses)
	require.Nil(t, collectAddresses(nil))
}
