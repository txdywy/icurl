use crate::evidence::{Assessment, AssessmentLevel, ErrorKind, Layer, ProbeResult, ProbeResultStatus};

pub fn classify(results: &[ProbeResult]) -> Assessment {
    let reasons = collect_reasons(results);

    if has_dns_interference(results) {
        return assessment(
            AssessmentLevel::SuspiciousHigh,
            "DNS_INTERFERENCE_PATTERN",
            "DNS response pattern suggests interference.",
            reasons,
        );
    }
    if has_certificate_error(results) {
        return assessment(
            AssessmentLevel::Fail,
            "TLS_CERTIFICATE_ERROR",
            "TCP connects but TLS fails due to a certificate error.",
            reasons,
        );
    }
    if has_tls_interruption(results) {
        return assessment(
            AssessmentLevel::SuspiciousHigh,
            "TLS_SNI_INTERRUPTION_PATTERN",
            "TCP succeeds but TLS is reset, suggesting TLS/SNI interruption.",
            reasons,
        );
    }
    if has_quic_blockage(results) {
        return assessment(
            AssessmentLevel::SuspiciousMedium,
            "UDP_QUIC_BLOCKAGE_PATTERN",
            "TCP and TLS succeed while QUIC times out, suggesting UDP/QUIC blockage.",
            reasons,
        );
    }
    if has_http_origin_failure(results) {
        return assessment(
            AssessmentLevel::Fail,
            "HTTP_ORIGIN_FAILURE",
            "DNS, TCP, and TLS succeed but HTTP fails at the origin.",
            reasons,
        );
    }
    if all_ok_or_skipped(results) {
        return assessment(
            AssessmentLevel::Pass,
            "PASS",
            "All probes passed or were skipped.",
            reasons,
        );
    }
    assessment(
        AssessmentLevel::Unknown,
        "INSUFFICIENT_EVIDENCE",
        "Probe results are insufficient for a specific assessment.",
        reasons,
    )
}

fn collect_reasons(results: &[ProbeResult]) -> Vec<String> {
    let mut reasons = Vec::new();
    for result in results {
        if let Some(ref msg) = result.error_message {
            reasons.push(format!("{}: {}", result.probe_name, msg));
        }
        if let Some(ref obs) = result.observations {
            for observation in obs {
                reasons.push(format!("{}: {}", result.probe_name, observation));
            }
        }
    }
    reasons
}

fn assessment(
    level: AssessmentLevel,
    category: &str,
    summary: &str,
    reasons: Vec<String>,
) -> Assessment {
    Assessment {
        level,
        category: category.to_string(),
        summary: summary.to_string(),
        reasons,
        next_steps: Vec::new(),
    }
}

fn has_dns_interference(results: &[ProbeResult]) -> bool {
    for result in results {
        if result.layer == Layer::Dns
            && result.result == ProbeResultStatus::Failed
            && result.error_kind == ErrorKind::SuspiciousDns
        {
            return true;
        }
    }
    false
}

fn has_tls_interruption(results: &[ProbeResult]) -> bool {
    has_layer_result(results, Layer::Tcp, ProbeResultStatus::Ok)
        && (has_layer_failure(results, Layer::Tls, ErrorKind::Reset)
            || has_layer_failure_unknown(results, Layer::Tls))
        && has_layer_result(results, Layer::Tls, ProbeResultStatus::Failed)
}

fn has_certificate_error(results: &[ProbeResult]) -> bool {
    has_layer_result(results, Layer::Tcp, ProbeResultStatus::Ok)
        && has_layer_failure(results, Layer::Tls, ErrorKind::Certificate)
}

fn has_quic_blockage(results: &[ProbeResult]) -> bool {
    has_layer_result(results, Layer::Tcp, ProbeResultStatus::Ok)
        && has_layer_result(results, Layer::Tls, ProbeResultStatus::Ok)
        && has_layer_result(results, Layer::Quic, ProbeResultStatus::Timeout)
}

fn has_http_origin_failure(results: &[ProbeResult]) -> bool {
    has_layer_result(results, Layer::Dns, ProbeResultStatus::Ok)
        && has_layer_result(results, Layer::Tcp, ProbeResultStatus::Ok)
        && has_layer_result(results, Layer::Tls, ProbeResultStatus::Ok)
        && has_layer_result(results, Layer::Http, ProbeResultStatus::Failed)
}

fn all_ok_or_skipped(results: &[ProbeResult]) -> bool {
    if results.is_empty() {
        return false;
    }
    for result in results {
        if result.result != ProbeResultStatus::Ok && result.result != ProbeResultStatus::Skipped {
            return false;
        }
    }
    true
}

fn has_layer_result(results: &[ProbeResult], layer: Layer, expected: ProbeResultStatus) -> bool {
    for result in results {
        if result.layer == layer && result.result == expected {
            return true;
        }
    }
    false
}

fn has_layer_failure(results: &[ProbeResult], layer: Layer, kind: ErrorKind) -> bool {
    for result in results {
        if result.layer == layer
            && result.result == ProbeResultStatus::Failed
            && result.error_kind == kind
        {
            return true;
        }
    }
    false
}

fn has_layer_failure_unknown(results: &[ProbeResult], layer: Layer) -> bool {
    for result in results {
        if result.layer == layer && result.result == ProbeResultStatus::Failed {
            if let ErrorKind::Unknown = result.error_kind {
                return true;
            }
        }
    }
    false
}
