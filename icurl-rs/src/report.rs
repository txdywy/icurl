use std::collections::BTreeMap;
use std::io::Write;

use anyhow::Result;
use base64::Engine;
use serde::Serialize;

use crate::diagnose::DiagnoseResult;
use crate::request::{Redirect, RequestResult};

pub struct RequestHumanOptions {
    pub include_headers: bool,
}

pub fn write_request_human<W: Write>(
    w: &mut W,
    result: &RequestResult,
    opts: &RequestHumanOptions,
) -> Result<()> {
    if opts.include_headers {
        writeln!(w, "{} {}", result.protocol, result.status_code)?;

        for (name, values) in &result.response_headers {
            for value in values {
                writeln!(w, "{}: {}", name, value)?;
            }
        }
        writeln!(w)?;
    }

    w.write_all(&result.body)?;
    Ok(())
}

#[derive(Serialize)]
struct RequestJson {
    url: String,
    status_code: u16,
    protocol: String,
    headers: BTreeMap<String, Vec<String>>,
    body_base64: String,
    redirects: Vec<Redirect>,
}

pub fn write_request_json<W: Write>(w: &mut W, result: &RequestResult) -> Result<()> {
    let payload = RequestJson {
        url: result.url.clone(),
        status_code: result.status_code,
        protocol: result.protocol.clone(),
        headers: result.response_headers.clone(),
        body_base64: base64::engine::general_purpose::STANDARD.encode(&result.body),
        redirects: result.redirects.clone(),
    };
    let json = serde_json::to_string_pretty(&payload)?;
    writeln!(w, "{}", json)?;
    Ok(())
}

pub fn write_diagnose_human<W: Write>(w: &mut W, result: &DiagnoseResult) -> Result<()> {
    writeln!(w, "Target: {}\n", result.target)?;
    writeln!(w, "Layer summary:")?;
    for probe in &result.probe_results {
        writeln!(
            w,
            "  {:<5} {:<8} {}",
            probe.layer,
            probe.result,
            probe.error_message_str()
        )?;
    }
    writeln!(w)?;
    writeln!(w, "Assessment:")?;
    writeln!(w, "  Level: {}", result.assessment.level)?;
    writeln!(w, "  Category: {}", result.assessment.category)?;
    writeln!(w, "  Summary: {}", result.assessment.summary)?;
    if !result.assessment.reasons.is_empty() {
        writeln!(w, "Reasons:")?;
        for reason in &result.assessment.reasons {
            writeln!(w, "  - {}", reason)?;
        }
    }
    if !result.assessment.next_steps.is_empty() {
        writeln!(w, "Next steps:")?;
        for step in &result.assessment.next_steps {
            writeln!(w, "  - {}", step)?;
        }
    }
    if let Some(ref path) = result.capture_path {
        writeln!(w, "Packet capture: {}", path)?;
    }
    Ok(())
}

pub fn write_diagnose_json<W: Write>(w: &mut W, result: &DiagnoseResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    writeln!(w, "{}", json)?;
    Ok(())
}
