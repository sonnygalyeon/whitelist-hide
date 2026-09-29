use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

const BODY_LIMIT: u64 = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(6);
pub const REQUIRED_TARGETS: [&str; 4] =
    ["youtube-web", "youtube-image", "discord-api", "discord-cdn"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeResult {
    pub target: String,
    pub ok: bool,
    pub elapsed_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeReport {
    pub results: Vec<ProbeResult>,
}

impl ProbeReport {
    pub fn successful(&self) -> bool {
        REQUIRED_TARGETS.iter().all(|id| {
            self.results.iter().filter(|r| &r.target == id).count() == 1
                && self.results.iter().any(|r| &r.target == id && r.ok)
        })
    }
}

pub trait Prober {
    fn probe(&mut self) -> ProbeReport;
}

#[derive(Default)]
pub struct HttpsProber;

impl Prober for HttpsProber {
    fn probe(&mut self) -> ProbeReport {
        // New connections for every sweep: an old keep-alive connection must
        // never make a newly selected strategy look successful. No proxy fallback.
        let client = Client::builder()
            .no_proxy()
            .http1_only()
            .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(TIMEOUT)
            .pool_max_idle_per_host(0)
            .user_agent("WhiteHide-Connectivity/1")
            .build();
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = TARGETS
                .iter()
                .map(|target| {
                    let client = &client;
                    scope.spawn(move || {
                        probe_target(client.as_ref().map_err(|e| e.to_string()), target)
                    })
                })
                .collect();
            handles
                .into_iter()
                .enumerate()
                .map(|(i, h)| {
                    h.join().unwrap_or_else(|_| ProbeResult {
                        target: TARGETS[i].id.into(),
                        ok: false,
                        elapsed_ms: 0,
                        detail: "probe worker failed".into(),
                    })
                })
                .collect()
        });
        ProbeReport { results }
    }
}

struct Target {
    id: &'static str,
    url: &'static str,
}
const TARGETS: [Target; 4] = [
    Target {
        id: "youtube-web",
        url: "https://www.youtube.com/generate_204",
    },
    Target {
        id: "youtube-image",
        url: "https://i.ytimg.com/vi/jNQXAC9IVRw/default.jpg",
    },
    Target {
        id: "discord-api",
        url: "https://discord.com/api/v10/gateway",
    },
    Target {
        id: "discord-cdn",
        url: "https://cdn.discordapp.com/embed/avatars/0.png",
    },
];

fn probe_target(client: Result<&Client, String>, target: &Target) -> ProbeResult {
    let started = Instant::now();
    let result = (|| -> Result<(), String> {
        let client = client?;
        let response = client
            .get(target.url)
            .header("Connection", "close")
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    "timeout".into()
                } else {
                    format!("HTTPS/DNS/connect error: {e}")
                }
            })?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut body = Vec::new();
        response
            .take(BODY_LIMIT + 1)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;
        if body.len() as u64 > BODY_LIMIT {
            return Err("response exceeds probe limit".into());
        }
        validate_response(target.id, status, &content_type, &body)
    })();
    ProbeResult {
        target: target.id.into(),
        ok: result.is_ok(),
        elapsed_ms: started.elapsed().as_millis() as u64,
        detail: result
            .err()
            .unwrap_or_else(|| "HTTPS IPv4: expected response verified".into()),
    }
}

fn validate_response(id: &str, status: u16, content_type: &str, body: &[u8]) -> Result<(), String> {
    let valid = match id {
        "youtube-web" => status == 204 && body.is_empty(),
        "youtube-image" => {
            status == 200
                && content_type.starts_with("image/jpeg")
                && body.starts_with(&[0xff, 0xd8, 0xff])
        }
        "discord-cdn" => {
            status == 200
                && content_type.starts_with("image/png")
                && body.starts_with(b"\x89PNG\r\n\x1a\n")
        }
        "discord-api" => {
            status == 200
                && serde_json::from_slice::<serde_json::Value>(body)
                    .ok()
                    .and_then(|json| json.get("url").and_then(|v| v.as_str()).map(str::to_owned))
                    .is_some_and(|url| {
                        matches!(
                            url.as_str(),
                            "wss://gateway.discord.gg" | "wss://gateway.discord.gg/"
                        )
                    })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "unexpected response (HTTP {status}); access not confirmed"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_block_pages_redirects_rate_limits_and_wrong_payloads() {
        for status in [200, 301, 403, 429, 503] {
            assert!(validate_response("youtube-web", status, "text/html", b"blocked").is_err());
        }
        assert!(
            validate_response(
                "discord-api",
                200,
                "application/json",
                br#"{"url":"wss://wrong.example"}"#
            )
            .is_err()
        );
        assert!(validate_response("discord-cdn", 200, "image/png", b"blocked").is_err());
        assert!(validate_response("youtube-web", 204, "", b"").is_ok());
        assert!(
            validate_response(
                "discord-api",
                200,
                "application/json",
                br#"{"url":"wss://gateway.discord.gg"}"#
            )
            .is_ok()
        );
    }
    #[test]
    fn missing_results_are_never_success() {
        assert!(!ProbeReport::default().successful());
        assert!(
            !ProbeReport {
                results: vec![ProbeResult {
                    target: "youtube-web".into(),
                    ok: true,
                    elapsed_ms: 0,
                    detail: String::new()
                }]
            }
            .successful()
        );
    }
}
