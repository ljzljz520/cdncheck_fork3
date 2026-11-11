package cdncheck

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/projectdiscovery/retryabledns"
)

// Domain identification outcomes.
const (
	// DomainStatusMatched means positive CDN/WAF/Cloud evidence was found
	// in an address record or a CNAME suffix.
	DomainStatusMatched = "matched"
	// DomainStatusMissed means every required query completed with usable
	// data and no provider evidence was found. The result is conclusive and
	// safe to use as an exclusion target.
	DomainStatusMissed = "missed"
	// DomainStatusUndetermined means a required query failed or returned no
	// usable data, so neither a match nor a miss can be confirmed.
	DomainStatusUndetermined = "undetermined"
)

// Per-query completion states recorded in QueryDiagnostic.
const (
	QueryStatusCompleted = "completed"
	QueryStatusFailed    = "failed"
	QueryStatusSkipped   = "skipped"
)

// DNS query stage names.
const (
	StageAddress = "address"
	StageCNAME   = "cname"
)

// ErrDomainUndetermined is wrapped (always retrievable via errors.Is) by the
// error returned through the legacy CheckDomainWithFallback signature when a
// domain can neither be matched nor conclusively cleared.
var ErrDomainUndetermined = errors.New("cdncheck: domain identification undetermined")

// QueryDiagnostic records the completion state of one DNS query stage
// (the A/AAAA address query or the CNAME fallback) and the reason of its
// failure when it did not complete.
type QueryDiagnostic struct {
	// Stage is either StageAddress or StageCNAME.
	Stage string `json:"stage"`
	// Status is one of QueryStatusCompleted, QueryStatusFailed or
	// QueryStatusSkipped.
	Status string `json:"status"`
	// Reason describes why the stage did not complete conclusively.
	Reason string `json:"reason,omitempty"`
	// StatusCode is the DNS rcode name (e.g. "NXDOMAIN") when a response
	// was received.
	StatusCode string `json:"status_code,omitempty"`
	// RecordCount is the number of usable records returned by the stage.
	RecordCount int `json:"record_count,omitempty"`
}

// DomainCheckResult is the detailed outcome of a domain identification run.
// It distinguishes confirmed matches, confirmed misses and undetermined
// inputs and carries the completion state of every underlying DNS query.
type DomainCheckResult struct {
	// Input is the domain that was checked.
	Input string `json:"input"`
	// Status is one of DomainStatusMatched, DomainStatusMissed or
	// DomainStatusUndetermined.
	Status string `json:"status"`
	// Matched reports whether provider evidence was found.
	Matched bool `json:"matched"`
	// Provider is the matched provider name, empty when not matched.
	Provider string `json:"provider,omitempty"`
	// ItemType is the matched item type ("cdn", "waf" or "cloud").
	ItemType string `json:"item_type,omitempty"`
	// IP is the first usable resolved address, if any.
	IP string `json:"ip,omitempty"`
	// Addresses are all parseable addresses returned by the address query.
	Addresses []string `json:"addresses,omitempty"`
	// CNAMEs are all CNAME records observed across both query stages.
	CNAMEs []string `json:"cnames,omitempty"`
	// AddressQuery reports the completion state of the A/AAAA resolution.
	AddressQuery QueryDiagnostic `json:"address_query"`
	// CNAMEQuery reports the completion state of the CNAME fallback. It is
	// marked skipped when the address response already matched.
	CNAMEQuery QueryDiagnostic `json:"cname_query"`
	// Reasons explains why the result is undetermined, one entry per
	// incomplete stage. Empty for matched and missed results.
	Reasons []string `json:"reasons,omitempty"`

	underlying error
}

// HasUsableAddress reports whether at least one parseable address was
// resolved. Only results with usable addresses may be treated as confirmed
// exclusion targets.
func (r *DomainCheckResult) HasUsableAddress() bool {
	return len(r.Addresses) > 0
}

// Err returns a non-nil error wrapping ErrDomainUndetermined when the result
// is undetermined, otherwise nil.
func (r *DomainCheckResult) Err() error {
	if r.Status != DomainStatusUndetermined {
		return nil
	}
	message := strings.Join(r.Reasons, "; ")
	if message == "" {
		message = "inconclusive domain identification"
	}
	if r.underlying != nil {
		return fmt.Errorf("%w: %s: %v", ErrDomainUndetermined, message, r.underlying)
	}
	return fmt.Errorf("%w: %s", ErrDomainUndetermined, message)
}

// CheckDomainWithFallbackDetailed works like CheckDomainWithFallback but
// returns the full three-state DomainCheckResult, including the completion
// state and failure reasons of the address query and the CNAME fallback.
func (c *Client) CheckDomainWithFallbackDetailed(domain string) *DomainCheckResult {
	addrData, addrErr := c.retriabledns.Resolve(domain)

	// Positive evidence in the address response is authoritative even when
	// the resolution returned a partial error, so the CNAME fallback can be
	// skipped in that case.
	if addrData != nil {
		if matched, _, _, _ := c.CheckDNSResponse(addrData); matched {
			return c.evaluateDomainResult(domain, addrData, addrErr, nil, nil, true)
		}
	}

	cnameData, cnameErr := c.retriabledns.CNAME(domain)
	return c.evaluateDomainResult(domain, addrData, addrErr, cnameData, cnameErr, false)
}

// evaluateDomainResult builds the three-state result from the raw outputs of
// both DNS stages. It takes the stage errors explicitly so it can be exercised
// deterministically with crafted DNS responses in tests. When cnameSkipped is
// true the CNAME stage diagnostic is marked skipped and cnameData/cnameErr are
// ignored.
func (c *Client) evaluateDomainResult(domain string, addrData *retryabledns.DNSData, addrErr error, cnameData *retryabledns.DNSData, cnameErr error, cnameSkipped bool) *DomainCheckResult {
	result := &DomainCheckResult{Input: domain}
	// checkErrors holds failures of the in-memory response checks themselves;
	// they only matter when no conclusive status can be reached.
	var checkErrors []string

	addressQuery, addresses := diagnoseAddressQuery(addrData, addrErr)
	result.AddressQuery = addressQuery
	result.Addresses = addresses
	if len(addresses) > 0 {
		result.IP = addresses[0]
	}
	result.CNAMEs = collectCNAMEs(addrData)

	if matched, provider, itemType, matchErr := c.matchDNSResponse(addrData); matchErr != nil {
		checkErrors = append(checkErrors, fmt.Sprintf("address response check failed: %s", matchErr.Error()))
	} else if matched {
		result.setMatch(provider, itemType)
		result.CNAMEQuery = skippedQuery(StageCNAME, "address response already matched")
		return result
	}

	if cnameSkipped {
		result.CNAMEQuery = skippedQuery(StageCNAME, "address response already matched")
	} else {
		result.CNAMEQuery = diagnoseCNAMEQuery(cnameData, cnameErr)
		result.CNAMEs = append(result.CNAMEs, collectCNAMEs(cnameData)...)
		if matched, provider, itemType, matchErr := c.matchDNSResponse(cnameData); matchErr != nil {
			checkErrors = append(checkErrors, fmt.Sprintf("cname response check failed: %s", matchErr.Error()))
		} else if matched {
			result.setMatch(provider, itemType)
			return result
		}
	}

	result.underlying = errors.Join(addrErr, cnameErr)

	addressConclusive := result.AddressQuery.Status == QueryStatusCompleted
	cnameConclusive := cnameSkipped || result.CNAMEQuery.Status == QueryStatusCompleted
	if result.HasUsableAddress() && addressConclusive && cnameConclusive {
		result.Status = DomainStatusMissed
		return result
	}

	result.Status = DomainStatusUndetermined
	result.Reasons = append(result.Reasons, checkErrors...)
	if !result.HasUsableAddress() {
		result.Reasons = append(result.Reasons, fmt.Sprintf("address query incomplete: %s", result.AddressQuery.Reason))
	}
	if !cnameSkipped && result.CNAMEQuery.Status == QueryStatusFailed {
		result.Reasons = append(result.Reasons, fmt.Sprintf("cname fallback incomplete: %s", result.CNAMEQuery.Reason))
	}
	return result
}

// matchDNSResponse is a nil-safe wrapper around CheckDNSResponse.
func (c *Client) matchDNSResponse(data *retryabledns.DNSData) (matched bool, provider string, itemType string, err error) {
	if data == nil {
		return false, "", "", nil
	}
	return c.CheckDNSResponse(data)
}

// setMatch records a positive identification on the result.
func (r *DomainCheckResult) setMatch(provider, itemType string) {
	r.Status = DomainStatusMatched
	r.Matched = true
	r.Provider = provider
	r.ItemType = itemType
}

// diagnoseAddressQuery turns the raw Resolve output into a stage diagnostic.
// A response carrying at least one parseable address counts as completed even
// when a partial error is attached (e.g. one of A/AAAA timed out while the
// other succeeded); the partial error is retained in Reason. Transport
// failures and definitive responses without usable addresses (NXDOMAIN,
// empty NOERROR) count as failed.
func diagnoseAddressQuery(data *retryabledns.DNSData, queryErr error) (QueryDiagnostic, []string) {
	diagnostic := QueryDiagnostic{Stage: StageAddress}
	addresses := collectAddresses(data)
	diagnostic.RecordCount = len(addresses)
	if data != nil && data.StatusCode != "" {
		diagnostic.StatusCode = data.StatusCode
	}

	if len(addresses) > 0 {
		diagnostic.Status = QueryStatusCompleted
		if queryErr != nil {
			diagnostic.Reason = "partial resolution error after usable address records: " + queryErr.Error()
		}
		return diagnostic, addresses
	}

	diagnostic.Status = QueryStatusFailed
	if queryErr != nil {
		diagnostic.Reason = queryErr.Error()
	} else {
		rcode := "unknown"
		if data != nil && data.StatusCode != "" {
			rcode = data.StatusCode
		}
		diagnostic.Reason = fmt.Sprintf("no usable address record in DNS response (rcode=%s)", rcode)
	}
	return diagnostic, nil
}

// diagnoseCNAMEQuery turns the raw CNAME fallback output into a stage
// diagnostic. A transport/retry failure or a missing response counts as
// failed; a definitive response, even one without CNAME records, counts as
// completed.
func diagnoseCNAMEQuery(data *retryabledns.DNSData, queryErr error) QueryDiagnostic {
	diagnostic := QueryDiagnostic{Stage: StageCNAME}
	if data != nil {
		if data.StatusCode != "" {
			diagnostic.StatusCode = data.StatusCode
		}
		diagnostic.RecordCount = len(data.CNAME)
	}
	if queryErr != nil {
		diagnostic.Status = QueryStatusFailed
		diagnostic.Reason = queryErr.Error()
		return diagnostic
	}
	if data == nil {
		diagnostic.Status = QueryStatusFailed
		diagnostic.Reason = "no DNS response received for CNAME query"
		return diagnostic
	}
	diagnostic.Status = QueryStatusCompleted
	return diagnostic
}

func skippedQuery(stage, reason string) QueryDiagnostic {
	return QueryDiagnostic{Stage: stage, Status: QueryStatusSkipped, Reason: reason}
}

// collectAddresses returns the parseable AAAA then A records of a response,
// mirroring the evaluation order of CheckDNSResponse.
func collectAddresses(data *retryabledns.DNSData) []string {
	if data == nil {
		return nil
	}
	addresses := make([]string, 0, len(data.AAAA)+len(data.A))
	for _, ip := range data.AAAA {
		if net.ParseIP(ip) != nil {
			addresses = append(addresses, ip)
		}
	}
	for _, ip := range data.A {
		if net.ParseIP(ip) != nil {
			addresses = append(addresses, ip)
		}
	}
	return addresses
}

func collectCNAMEs(data *retryabledns.DNSData) []string {
	if data == nil || len(data.CNAME) == 0 {
		return nil
	}
	return append([]string{}, data.CNAME...)
}

// legacyDomainResult maps a detailed three-state result onto the historical
// (matched, provider, itemType, err) return contract.
func legacyDomainResult(result *DomainCheckResult) (matched bool, provider string, itemType string, err error) {
	if result.Matched {
		return true, result.Provider, result.ItemType, nil
	}
	if result.Status == DomainStatusMissed {
		return false, "", "", nil
	}
	return false, "", "", result.Err()
}
