use clap::{Parser, Subcommand};
use icurl::diagnose::{DiagnoseConfig, DiagnoseEngine};
use icurl::report::{
    write_diagnose_human, write_diagnose_json, write_request_human, write_request_json,
    RequestHumanOptions,
};
use icurl::request::{Config as ReqConfig, Protocol as ReqProtocol};
use std::process::ExitCode;
use std::time::Duration;
use url::Url;

#[derive(Parser, Debug)]
#[command(name = "icurl", version = "0.1.0", about = "A network diagnostic curl-like tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Request URL
    url: Option<String>,

    /// Custom request method
    #[arg(short = 'X', long = "request")]
    method: Option<String>,

    /// Custom headers in Name: value format
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Request body data
    #[arg(short = 'd', long = "data")]
    data: Option<String>,

    /// Send HEAD request instead of GET
    #[arg(short = 'I', long = "head")]
    head: bool,

    /// Include response headers in output
    #[arg(short = 'i', long = "include")]
    include: bool,

    /// Follow redirects
    #[arg(short = 'L', long = "location")]
    location: bool,

    /// Connection timeout (e.g. "10s")
    #[arg(long = "connect-timeout", default_value = "10s")]
    connect_timeout: String,

    /// Total timeout (e.g. "30s")
    #[arg(long = "max-time", default_value = "30s")]
    max_time: String,

    /// Force HTTP/1.1
    #[arg(long = "http1.1")]
    http1_1: bool,

    /// Force HTTP/2
    #[arg(long = "http2")]
    http2: bool,

    /// Prefer HTTP/3 (Note: currently mapped to default or HTTP/3 if supported)
    #[arg(long = "http3")]
    http3: bool,

    /// Force HTTP/3 only
    #[arg(long = "http3-only")]
    http3_only: bool,

    /// Run diagnostics on failure
    #[arg(long = "diagnose")]
    diagnose: bool,

    /// Write JSON output
    #[arg(long = "json")]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run diagnostics on the specified URL
    Diagnose {
        /// URL to diagnose
        url: String,

        /// Run deep diagnostics (requires sudo)
        #[arg(long = "deep")]
        deep: bool,

        /// Write JSON output
        #[arg(long = "json")]
        json: bool,
    },
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    let mut num_end = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() || c == '.' {
            num_end = i + 1;
        } else {
            break;
        }
    }

    if num_end == 0 {
        return Err(format!("invalid duration: {}", s));
    }

    let num_str = &s[..num_end];
    let val: f64 = num_str
        .parse()
        .map_err(|_| format!("invalid number: {}", num_str))?;
    let unit = &s[num_end..];

    match unit {
        "ms" => Ok(Duration::from_secs_f64(val / 1000.0)),
        "s" | "" => Ok(Duration::from_secs_f64(val)),
        "m" => Ok(Duration::from_secs_f64(val * 60.0)),
        "h" => Ok(Duration::from_secs_f64(val * 3600.0)),
        _ => Err(format!("unknown duration unit: {}", unit)),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let _ = rustls::crypto::ring::default_provider().install_default();

    if cli.url.is_none() && cli.command.is_none() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        println!();
        return ExitCode::from(2);
    }

    // Check protocol options
    let mut selected_protocols = 0;
    if cli.http1_1 { selected_protocols += 1; }
    if cli.http2 { selected_protocols += 1; }
    if cli.http3 { selected_protocols += 1; }
    if cli.http3_only { selected_protocols += 1; }
    if selected_protocols > 1 {
        eprintln!("icurl: choose only one HTTP protocol flag");
        return ExitCode::from(2);
    }

    let protocol = if cli.http1_1 {
        ReqProtocol::Http11
    } else if cli.http2 {
        ReqProtocol::Http2
    } else if cli.http3 {
        ReqProtocol::Http3
    } else if cli.http3_only {
        ReqProtocol::Http3Only
    } else {
        ReqProtocol::Auto
    };

    if let Some(command) = cli.command {
        match command {
            Commands::Diagnose { url, deep, json } => {
                let parsed_url = match Url::parse(&url) {
                    Ok(u) => u,
                    Err(e) => {
                        eprintln!("icurl: invalid URL: {}", e);
                        return ExitCode::from(2);
                    }
                };

                let config = DiagnoseConfig {
                    url: parsed_url,
                    deep,
                };

                let engine = DiagnoseEngine::new();
                let result = engine.run(config).await;

                if json {
                    let mut stdout = std::io::stdout();
                    if let Err(e) = write_diagnose_json(&mut stdout, &result) {
                        eprintln!("icurl: {}", e);
                        return ExitCode::from(1);
                    }
                } else {
                    let mut stdout = std::io::stdout();
                    if let Err(e) = write_diagnose_human(&mut stdout, &result) {
                        eprintln!("icurl: {}", e);
                        return ExitCode::from(1);
                    }
                }
                ExitCode::from(0)
            }
        }
    } else {
        // Run standard curl request
        let url_str = cli.url.unwrap();
        let parsed_url = match Url::parse(&url_str) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("icurl: invalid URL: {}", e);
                return ExitCode::from(2);
            }
        };

        let connect_timeout = match parse_duration(&cli.connect_timeout) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("icurl: invalid --connect-timeout: {}", e);
                return ExitCode::from(2);
            }
        };

        let max_time = match parse_duration(&cli.max_time) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("icurl: invalid --max-time: {}", e);
                return ExitCode::from(2);
            }
        };

        let mut headers = Vec::new();
        for h in cli.headers {
            if let Some((name, val)) = h.split_once(':') {
                let name = name.trim().to_string();
                let val = val.trim().to_string();
                if name.is_empty() {
                    eprintln!("icurl: header name cannot be empty");
                    return ExitCode::from(2);
                }
                headers.push((name, val));
            } else {
                eprintln!("icurl: header must be in Name: value form");
                return ExitCode::from(2);
            }
        }

        let config = ReqConfig {
            url: parsed_url.to_string(),
            host: parsed_url.host_str().unwrap_or("").to_string(),
            method: cli.method.unwrap_or_default(),
            headers,
            body: cli.data.unwrap_or_default(),
            head: cli.head,
            include_headers: cli.include,
            follow_redirect: cli.location,
            connect_timeout,
            max_time,
            protocol,
            diagnose: cli.diagnose,
            json_output: cli.json,
        };

        match icurl::request::execute(&config).await {
            Ok(result) => {
                if cli.json {
                    let mut stdout = std::io::stdout();
                    if let Err(e) = write_request_json(&mut stdout, &result) {
                        eprintln!("icurl: {}", e);
                        return ExitCode::from(1);
                    }
                } else {
                    let mut stdout = std::io::stdout();
                    let opts = RequestHumanOptions {
                        include_headers: cli.include,
                    };
                    if let Err(e) = write_request_human(&mut stdout, &result, &opts) {
                        eprintln!("icurl: {}", e);
                        return ExitCode::from(1);
                    }
                }
                ExitCode::from(0)
            }
            Err(err) => {
                eprintln!("icurl: {:?}", err);
                if cli.diagnose {
                    // Trigger diagnostics
                    let diag_config = DiagnoseConfig {
                        url: parsed_url,
                        deep: false,
                    };
                    let engine = DiagnoseEngine::new();
                    let diag_result = engine.run(diag_config).await;

                    if cli.json {
                        let mut stdout = std::io::stdout();
                        let _ = write_diagnose_json(&mut stdout, &diag_result);
                    } else {
                        let mut stdout = std::io::stdout();
                        let _ = write_diagnose_human(&mut stdout, &diag_result);
                    }
                }
                ExitCode::from(1)
            }
        }
    }
}
