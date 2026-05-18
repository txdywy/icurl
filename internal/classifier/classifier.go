package classifier

import "icurl/internal/evidence"

func Classify(results []evidence.ProbeResult) evidence.Assessment {
	reasons := collectReasons(results)

	if hasDNSInterference(results) {
		return assessment(evidence.AssessmentSuspiciousHigh, "DNS_INTERFERENCE_PATTERN", "DNS response pattern suggests interference.", reasons)
	}
	if hasTLSInterruption(results) {
		return assessment(evidence.AssessmentSuspiciousHigh, "TLS_SNI_INTERRUPTION_PATTERN", "TCP succeeds but TLS is reset, suggesting TLS/SNI interruption.", reasons)
	}
	if hasQUICBlockage(results) {
		return assessment(evidence.AssessmentSuspiciousMedium, "UDP_QUIC_BLOCKAGE_PATTERN", "TCP and TLS succeed while QUIC times out, suggesting UDP/QUIC blockage.", reasons)
	}
	if hasHTTPOriginFailure(results) {
		return assessment(evidence.AssessmentFail, "HTTP_ORIGIN_FAILURE", "DNS, TCP, and TLS succeed but HTTP fails at the origin.", reasons)
	}
	if allOKOrSkipped(results) {
		return assessment(evidence.AssessmentPass, "PASS", "All probes passed or were skipped.", reasons)
	}
	return assessment(evidence.AssessmentUnknown, "INSUFFICIENT_EVIDENCE", "Probe results are insufficient for a specific assessment.", reasons)
}

func collectReasons(results []evidence.ProbeResult) []string {
	var reasons []string
	for _, result := range results {
		if result.ErrorMessage != "" {
			reasons = append(reasons, result.ProbeName+": "+result.ErrorMessage)
		}
		for _, observation := range result.Observations {
			reasons = append(reasons, result.ProbeName+": "+observation)
		}
	}
	return reasons
}

func assessment(level evidence.AssessmentLevel, category, summary string, reasons []string) evidence.Assessment {
	return evidence.Assessment{
		Level:     level,
		Category:  category,
		Summary:   summary,
		Reasons:   reasons,
		NextSteps: []string{},
	}
}

func hasDNSInterference(results []evidence.ProbeResult) bool {
	for _, result := range results {
		if result.Layer == evidence.LayerDNS && result.Result == evidence.ResultFailed && result.ErrorKind == evidence.ErrorSuspiciousDNS {
			return true
		}
	}
	return false
}

func hasTLSInterruption(results []evidence.ProbeResult) bool {
	return hasLayerResult(results, evidence.LayerTCP, evidence.ResultOK) && hasLayerFailure(results, evidence.LayerTLS, evidence.ErrorReset)
}

func hasQUICBlockage(results []evidence.ProbeResult) bool {
	return hasLayerResult(results, evidence.LayerTCP, evidence.ResultOK) &&
		hasLayerResult(results, evidence.LayerTLS, evidence.ResultOK) &&
		hasLayerResult(results, evidence.LayerQUIC, evidence.ResultTimeout)
}

func hasHTTPOriginFailure(results []evidence.ProbeResult) bool {
	return hasLayerResult(results, evidence.LayerDNS, evidence.ResultOK) &&
		hasLayerResult(results, evidence.LayerTCP, evidence.ResultOK) &&
		hasLayerResult(results, evidence.LayerTLS, evidence.ResultOK) &&
		hasLayerResult(results, evidence.LayerHTTP, evidence.ResultFailed)
}

func allOKOrSkipped(results []evidence.ProbeResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, result := range results {
		if result.Result != evidence.ResultOK && result.Result != evidence.ResultSkipped {
			return false
		}
	}
	return true
}

func hasLayerResult(results []evidence.ProbeResult, layer evidence.Layer, expected evidence.Result) bool {
	for _, result := range results {
		if result.Layer == layer && result.Result == expected {
			return true
		}
	}
	return false
}

func hasLayerFailure(results []evidence.ProbeResult, layer evidence.Layer, kind evidence.ErrorKind) bool {
	for _, result := range results {
		if result.Layer == layer && result.Result == evidence.ResultFailed && result.ErrorKind == kind {
			return true
		}
	}
	return false
}
