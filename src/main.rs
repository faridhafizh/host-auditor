use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
    response::IntoResponse,
    // routing::{get, post},
    routing::{get},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::info;
use uuid::Uuid;
use chrono::Utc;

// ─── State ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    scans: Arc<Mutex<HashMap<String, ScanJob>>>,
    config: Arc<Mutex<AIConfig>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct AIConfig {
    provider: String,
    model: String,
    api_key: String,
    base_url: Option<String>,
}

impl Default for AIConfig {
    fn default() -> Self {
        AIConfig {
            provider: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            api_key: String::new(),
            base_url: None,
        }
    }
}

// ─── Scan Models ─────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ScanJob {
    id: String,
    target: String,
    status: ScanStatus,
    started_at: String,
    completed_at: Option<String>,
    findings: Vec<Finding>,
    report: Option<String>,
    scan_type: String,
    progress: u8,
    log: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ScanStatus {
    Queued,
    Running,
    Analyzing,
    Done,
    Failed,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct Finding {
    id: String,
    severity: Severity,
    title: String,
    description: String,
    port: Option<u16>,
    service: Option<String>,
    cve: Option<Vec<String>>,
    recommendation: String,
    evidence: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

// ─── Request/Response Types ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct StartScanRequest {
    target: Option<String>,
    scan_type: String, // "quick", "full", "port", "web", "all"
}

#[derive(Deserialize)]
struct ConfigRequest {
    provider: String,
    model: String,
    api_key: String,
    base_url: Option<String>,
}

#[derive(Serialize)]
struct ScanListItem {
    id: String,
    target: String,
    status: ScanStatus,
    started_at: String,
    scan_type: String,
    finding_count: usize,
    severity_summary: HashMap<String, usize>,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "version": "1.0.0" }))
}

async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.lock().unwrap();
    let mut safe = cfg.clone();
    if !safe.api_key.is_empty() {
        safe.api_key = "••••••••".to_string();
    }
    Json(safe)
}

async fn set_config(
    State(state): State<AppState>,
    Json(req): Json<ConfigRequest>,
) -> impl IntoResponse {
    let mut cfg = state.config.lock().unwrap();
    cfg.provider = req.provider;
    cfg.model = req.model;
    cfg.api_key = req.api_key;
    cfg.base_url = req.base_url;
    Json(serde_json::json!({ "ok": true }))
}

async fn start_scan(
    State(state): State<AppState>,
    Json(req): Json<StartScanRequest>,
) -> impl IntoResponse {
    let target = req.target.unwrap_or_else(|| "127.0.0.1".to_string());
    let id = Uuid::new_v4().to_string();

    let job = ScanJob {
        id: id.clone(),
        target: target.clone(),
        status: ScanStatus::Queued,
        started_at: Utc::now().to_rfc3339(),
        completed_at: None,
        findings: vec![],
        report: None,
        scan_type: req.scan_type.clone(),
        progress: 0,
        log: vec![format!("Scan queued for target: {}", target)],
    };

    {
        let mut scans = state.scans.lock().unwrap();
        scans.insert(id.clone(), job);
    }

    // Spawn background task
    let state_clone = state.clone();
    let id_clone = id.clone();
    tokio::spawn(async move {
        run_scan(state_clone, id_clone).await;
    });

    Json(serde_json::json!({ "scan_id": id }))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let scans = state.scans.lock().unwrap();
    if let Some(scan) = scans.get(&id) {
        Json(scan.clone()).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response()
    }
}

async fn list_scans(State(state): State<AppState>) -> impl IntoResponse {
    let scans = state.scans.lock().unwrap();
    let mut items: Vec<ScanListItem> = scans
        .values()
        .map(|s| {
            let mut severity_summary: HashMap<String, usize> = HashMap::new();
            for f in &s.findings {
                let key = format!("{:?}", f.severity).to_uppercase();
                *severity_summary.entry(key).or_insert(0) += 1;
            }
            ScanListItem {
                id: s.id.clone(),
                target: s.target.clone(),
                status: s.status.clone(),
                started_at: s.started_at.clone(),
                scan_type: s.scan_type.clone(),
                finding_count: s.findings.len(),
                severity_summary,
            }
        })
        .collect();
    items.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    Json(items)
}

async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let scans = state.scans.lock().unwrap();
    if let Some(scan) = scans.get(&id) {
        if let Some(report) = &scan.report {
            return (
                StatusCode::OK,
                [("Content-Type", "text/markdown")],
                report.clone(),
            ).into_response();
        }
        return (StatusCode::ACCEPTED, [("Content-Type", "text/plain")], "Report not ready".to_string()).into_response();
    }
    (StatusCode::NOT_FOUND, [("Content-Type", "text/plain")], "Not found".to_string()).into_response()
}

async fn delete_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut scans = state.scans.lock().unwrap();
    scans.remove(&id);
    Json(serde_json::json!({ "ok": true }))
}

// ─── Scan Engine ─────────────────────────────────────────────────────────────

fn update_scan<F>(state: &AppState, id: &str, f: F)
where
    F: FnOnce(&mut ScanJob),
{
    let mut scans = state.scans.lock().unwrap();
    if let Some(scan) = scans.get_mut(id) {
        f(scan);
    }
}

fn log_scan(state: &AppState, id: &str, msg: &str) {
    update_scan(state, id, |s| {
        s.log.push(format!("[{}] {}", Utc::now().format("%H:%M:%S"), msg));
    });
}

async fn run_scan(state: AppState, id: String) {
    update_scan(&state, &id, |s| {
        s.status = ScanStatus::Running;
        s.progress = 5;
    });

    let target = {
        let scans = state.scans.lock().unwrap();
        scans.get(&id).map(|s| s.target.clone()).unwrap_or_default()
    };
    let scan_type = {
        let scans = state.scans.lock().unwrap();
        scans.get(&id).map(|s| s.scan_type.clone()).unwrap_or_default()
    };

    log_scan(&state, &id, &format!("Starting {} scan on {}", scan_type, target));

    let mut all_findings: Vec<Finding> = Vec::new();

    // 1. Port scan
    log_scan(&state, &id, "Running port discovery...");
    update_scan(&state, &id, |s| s.progress = 15);
    let port_findings = run_port_scan(&target, &scan_type).await;
    log_scan(&state, &id, &format!("Port scan complete. Found {} open ports.", port_findings.len()));
    all_findings.extend(port_findings);

    update_scan(&state, &id, |s| s.progress = 35);

    // 2. Service fingerprinting
    if scan_type != "port" {
        log_scan(&state, &id, "Fingerprinting services...");
        let svc_findings = run_service_checks(&target).await;
        log_scan(&state, &id, &format!("Service check complete. {} findings.", svc_findings.len()));
        all_findings.extend(svc_findings);
    }

    update_scan(&state, &id, |s| s.progress = 55);

    // 3. Web checks
    if scan_type == "web" || scan_type == "all" || scan_type == "full" {
        log_scan(&state, &id, "Running web vulnerability checks...");
        let web_findings = run_web_checks(&target).await;
        log_scan(&state, &id, &format!("Web checks complete. {} findings.", web_findings.len()));
        all_findings.extend(web_findings);
    }

    update_scan(&state, &id, |s| s.progress = 70);

    // Save findings
    update_scan(&state, &id, |s| {
        s.findings = all_findings.clone();
        s.status = ScanStatus::Analyzing;
        s.progress = 75;
    });

    // 4. AI Analysis
    log_scan(&state, &id, "Sending data to AI for analysis and report generation...");
    let cfg = state.config.lock().unwrap().clone();
    
    if !cfg.api_key.is_empty() {
        match run_ai_analysis(&cfg, &target, &all_findings, &scan_type).await {
            Ok((enhanced_findings, report)) => {
                log_scan(&state, &id, "AI analysis complete. Generating final report...");
                update_scan(&state, &id, |s| {
                    s.findings = enhanced_findings;
                    s.report = Some(report);
                    s.status = ScanStatus::Done;
                    s.completed_at = Some(Utc::now().to_rfc3339());
                    s.progress = 100;
                });
            }
            Err(e) => {
                log_scan(&state, &id, &format!("AI analysis error: {}. Generating basic report...", e));
                let basic_report = generate_basic_report(&target, &all_findings, &scan_type);
                update_scan(&state, &id, |s| {
                    s.report = Some(basic_report);
                    s.status = ScanStatus::Done;
                    s.completed_at = Some(Utc::now().to_rfc3339());
                    s.progress = 100;
                });
            }
        }
    } else {
        log_scan(&state, &id, "No AI provider configured. Generating static report...");
        let basic_report = generate_basic_report(&target, &all_findings, &scan_type);
        update_scan(&state, &id, |s| {
            s.report = Some(basic_report);
            s.status = ScanStatus::Done;
            s.completed_at = Some(Utc::now().to_rfc3339());
            s.progress = 100;
        });
    }

    log_scan(&state, &id, "Scan complete.");
}

// ─── Scanner Modules ─────────────────────────────────────────────────────────

async fn run_port_scan(target: &str, scan_type: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    // Use nmap if available, otherwise use basic TCP connect scan
    let port_range = match scan_type {
        "quick" => "1-1024",
        "full" | "all" => "1-65535",
        _ => "1-10000",
    };

    let nmap_result = Command::new("nmap")
        .args(["-sV", "--open", "-p", port_range, "--script", "banner", "-T4", target])
        .output();

    match nmap_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_nmap_output(&stdout, &mut findings);
        }
        Err(_) => {
            // Fallback: basic scan of common ports
            let common_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
                27017, 5984, 9200, 11211, 4444, 5555,
            ];
            
            for port in &common_ports {
                if check_port(target, *port).await {
                    let svc = service_name(*port);
                    let severity = port_severity(*port);
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        severity: severity.clone(),
                        title: format!("Open port: {}/{}", port, svc),
                        description: format!(
                            "Port {} ({}) is open and accepting connections on {}.",
                            port, svc, target
                        ),
                        port: Some(*port),
                        service: Some(svc.to_string()),
                        cve: None,
                        recommendation: port_recommendation(port),
                        evidence: format!("TCP connect to {}:{} succeeded", target, port),
                    });
                }
            }
        }
    }

    findings
}

fn parse_nmap_output(output: &str, findings: &mut Vec<Finding>) {
    for line in output.lines() {
        if line.contains("/tcp") && (line.contains("open") || line.contains("filtered")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let port_proto: Vec<&str> = parts[0].split('/').collect();
                if let Ok(port) = port_proto[0].parse::<u16>() {
                    let svc = if parts.len() > 2 { parts[2] } else { "unknown" };
                    let severity = port_severity(port);
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        severity,
                        title: format!("Open port {}: {}", port, svc),
                        description: format!("Port {} ({}) discovered open via nmap scan.", port, svc),
                        port: Some(port),
                        service: Some(svc.to_string()),
                        cve: None,
                        recommendation: port_recommendation(&port),
                        evidence: line.trim().to_string(),
                    });
                }
            }
        }
    }
}

async fn check_port(host: &str, port: u16) -> bool {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};
    
    let addr = format!("{}:{}", host, port);
    timeout(Duration::from_millis(800), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

async fn run_service_checks(target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for default/weak service configurations
    let checks: Vec<(u16, &str, &str)> = vec![
        (21, "ftp", "FTP service detected - transmits credentials in plaintext"),
        (23, "telnet", "Telnet service detected - unencrypted remote access"),
        (25, "smtp", "SMTP relay may be open - potential spam relay risk"),
        (161, "snmp", "SNMP service detected - may expose system information"),
        (3306, "mysql", "MySQL database port exposed - verify access controls"),
        (5432, "postgresql", "PostgreSQL port exposed - verify access controls"),
        (6379, "redis", "Redis port exposed - often runs without authentication"),
        (27017, "mongodb", "MongoDB port exposed - verify authentication enabled"),
        (9200, "elasticsearch", "Elasticsearch port exposed - often lacks authentication"),
        (11211, "memcached", "Memcached port exposed - no authentication by default"),
        (5984, "couchdb", "CouchDB port exposed - check authentication settings"),
    ];

    for (port, svc, desc) in checks {
        if check_port(target, port).await {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                severity: if [6379, 9200, 11211, 27017].contains(&port) {
                    Severity::High
                } else if [21, 23].contains(&port) {
                    Severity::Critical
                } else {
                    Severity::Medium
                },
                title: format!("Exposed {} service on port {}", svc.to_uppercase(), port),
                description: desc.to_string(),
                port: Some(port),
                service: Some(svc.to_string()),
                cve: service_cves(port),
                recommendation: format!(
                    "Restrict {} access with firewall rules. Ensure authentication is enforced.",
                    svc
                ),
                evidence: format!("Connection to {}:{} succeeded", target, port),
            });
        }
    }

    findings
}

async fn run_web_checks(target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let ports = [80u16, 443, 8080, 8443, 8888, 3000, 5000];
    
    for port in &ports {
        let scheme = if *port == 443 || *port == 8443 { "https" } else { "http" };
        let base = format!("{}://{}:{}", scheme, target, port);

        // Try to connect
        if let Ok(resp) = client.get(&base).send().await {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            
            // Security headers check
            let missing_headers = check_security_headers(&headers);
            for header in missing_headers {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    severity: Severity::Medium,
                    title: format!("Missing security header: {}", header),
                    description: format!(
                        "The web server on port {} is missing the {} security header.",
                        port, header
                    ),
                    port: Some(*port),
                    service: Some("http".to_string()),
                    cve: None,
                    recommendation: format!("Add the {} header to all HTTP responses.", header),
                    evidence: format!("GET {} returned status {} without {} header", base, status, header),
                });
            }

            // Check for common vulnerable paths
            let vuln_paths = [
                ("/.git/HEAD", "Git repository exposed"),
                ("/.env", "Environment file exposed"),
                ("/admin", "Admin panel accessible"),
                ("/phpinfo.php", "PHP info page exposed"),
                ("/wp-admin/", "WordPress admin panel accessible"),
                ("/.htaccess", "Apache config exposed"),
                ("/api/v1/users", "Unauthenticated API endpoint"),
                ("/actuator", "Spring Boot actuator exposed"),
                ("/swagger-ui.html", "Swagger UI exposed"),
                ("/graphql", "GraphQL endpoint exposed"),
                ("/debug", "Debug endpoint accessible"),
                ("/.DS_Store", "macOS metadata file exposed"),
            ];

            for (path, title) in &vuln_paths {
                if let Ok(r) = client.get(format!("{}{}", base, path)).send().await {
                    let s = r.status().as_u16();
                    if s < 400 {
                        findings.push(Finding {
                            id: Uuid::new_v4().to_string(),
                            severity: if path.contains(".env") || path.contains(".git") {
                                Severity::Critical
                            } else if path.contains("admin") || path.contains("api") {
                                Severity::High
                            } else {
                                Severity::Medium
                            },
                            title: title.to_string(),
                            description: format!(
                                "The path {} on port {} returned HTTP {} (accessible).",
                                path, port, s
                            ),
                            port: Some(*port),
                            service: Some("http".to_string()),
                            cve: path_cves(path),
                            recommendation: format!(
                                "Restrict access to {}. This resource should not be publicly accessible.",
                                path
                            ),
                            evidence: format!("GET {}{} returned HTTP {}", base, path, s),
                        });
                    }
                }
            }
        }
    }

    findings
}

fn check_security_headers(headers: &reqwest::header::HeaderMap) -> Vec<&'static str> {
    let required = [
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-xss-protection", "X-XSS-Protection"),
        ("strict-transport-security", "Strict-Transport-Security"),
        ("content-security-policy", "Content-Security-Policy"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ];
    
    required
        .iter()
        .filter(|(key, _)| !headers.contains_key(*key))
        .map(|(_, label)| *label)
        .collect()
}

// ─── AI Analysis ─────────────────────────────────────────────────────────────

async fn run_ai_analysis(
    cfg: &AIConfig,
    target: &str,
    findings: &[Finding],
    scan_type: &str,
) -> anyhow::Result<(Vec<Finding>, String)> {
    let findings_json = serde_json::to_string_pretty(findings)?;
    
    let prompt = format!(
        r#"You are an expert cybersecurity analyst. Analyze the following vulnerability scan results for target {} and produce a comprehensive security report.

SCAN TYPE: {}
RAW FINDINGS: {}

Please respond with a JSON object containing:
1. "enhanced_findings": array of findings with additional CVE references, CVSS scores, and detailed recommendations
2. "report": a comprehensive markdown security report including:
   - Executive Summary
   - Risk Assessment (overall risk level)
   - Detailed Findings (organized by severity)
   - Attack Vectors and Threat Scenarios  
   - Prioritized Remediation Roadmap
   - Conclusion

Format your response as valid JSON only."#,
        target, scan_type, findings_json
    );

    let (api_url, auth_header) = match cfg.provider.as_str() {
        "openai" => (
            cfg.base_url.clone().unwrap_or_else(|| "https://api.openai.com/v1/chat/completions".to_string()),
            format!("Bearer {}", cfg.api_key),
        ),
        "anthropic" => (
            "https://api.anthropic.com/v1/messages".to_string(),
            format!("x-api-key {}", cfg.api_key),
        ),
        "groq" => (
            "https://api.groq.com/openai/v1/chat/completions".to_string(),
            format!("Bearer {}", cfg.api_key),
        ),
        "together" => (
            "https://api.together.xyz/v1/chat/completions".to_string(),
            format!("Bearer {}", cfg.api_key),
        ),
        "ollama" => (
            cfg.base_url.clone().unwrap_or_else(|| "http://localhost:11434/v1/chat/completions".to_string()),
            "Bearer ollama".to_string(),
        ),
        "openrouter" => (
            "https://openrouter.ai/api/v1/chat/completions".to_string(),
            format!("Bearer {}", cfg.api_key),
        ),
        _ => (
            cfg.base_url.clone().unwrap_or_else(|| "https://api.openai.com/v1/chat/completions".to_string()),
            format!("Bearer {}", cfg.api_key),
        ),
    };

    let client = reqwest::Client::new();
    
    let body = if cfg.provider == "anthropic" {
        serde_json::json!({
            "model": cfg.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        })
    } else {
        serde_json::json!({
            "model": cfg.model,
            "max_tokens": 4096,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert penetration tester and security analyst. Always respond with valid JSON."
                },
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        })
    };

    let mut req = client.post(&api_url).header("Content-Type", "application/json");
    
    if cfg.provider == "anthropic" {
        req = req.header("x-api-key", &cfg.api_key)
                 .header("anthropic-version", "2023-06-01");
    } else {
        req = req.header("Authorization", &auth_header);
    }

    let resp = req.json(&body).send().await?;
    let json: serde_json::Value = resp.json().await?;

    let content = if cfg.provider == "anthropic" {
        json["content"][0]["text"].as_str().unwrap_or("{}").to_string()
    } else {
        json["choices"][0]["message"]["content"].as_str().unwrap_or("{}").to_string()
    };

    // Parse AI response
    let parsed: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|_| serde_json::json!({"report": content, "enhanced_findings": []}));

    let report = parsed["report"].as_str().unwrap_or(&content).to_string();
    let enhanced_findings: Vec<Finding> = serde_json::from_value(
        parsed["enhanced_findings"].clone()
    ).unwrap_or_else(|_| findings.to_vec());

    Ok((enhanced_findings, report))
}

fn generate_basic_report(target: &str, findings: &[Finding], scan_type: &str) -> String {
    let now = Utc::now().format("%Y-%m-%d %H:%M UTC");
    
    let critical: Vec<_> = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).collect();
    let high: Vec<_> = findings.iter().filter(|f| matches!(f.severity, Severity::High)).collect();
    let medium: Vec<_> = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).collect();
    let low: Vec<_> = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).collect();
    let info: Vec<_> = findings.iter().filter(|f| matches!(f.severity, Severity::Info)).collect();

    let overall_risk = if !critical.is_empty() {
        "CRITICAL"
    } else if !high.is_empty() {
        "HIGH"
    } else if !medium.is_empty() {
        "MEDIUM"
    } else {
        "LOW"
    };

    let mut report = format!(
        "# Security Vulnerability Assessment Report\n\n\
         **Target:** {}\n\
         **Scan Type:** {}\n\
         **Date:** {}\n\
         **Overall Risk:** {}\n\n\
         ---\n\n\
         ## Executive Summary\n\n\
         A {} security scan was performed on {}. The scan identified {} total findings across {} severity levels.\n\n\
         | Severity | Count |\n\
         |----------|-------|\n\
         | 🔴 Critical | {} |\n\
         | 🟠 High | {} |\n\
         | 🟡 Medium | {} |\n\
         | 🟢 Low | {} |\n\
         | ℹ️ Info | {} |\n\n\
         ---\n\n\
         ## Detailed Findings\n\n",
        target, scan_type, now, overall_risk,
        scan_type, target, findings.len(),
        [!critical.is_empty(), !high.is_empty(), !medium.is_empty(), !low.is_empty()].iter().filter(|&&b| b).count(),
        critical.len(), high.len(), medium.len(), low.len(), info.len()
    );

    for (i, finding) in findings.iter().enumerate() {
        let severity_icon = match finding.severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Info => "ℹ️",
        };
        
        report.push_str(&format!(
            "### {}. {} {}\n\n\
             **Severity:** {:?}\n\
             **Port/Service:** {}/{}\n\n\
             **Description:**\n{}\n\n\
             **Evidence:**\n```\n{}\n```\n\n\
             **Recommendation:**\n{}\n\n\
             ---\n\n",
            i + 1,
            severity_icon,
            finding.title,
            finding.severity,
            finding.port.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string()),
            finding.service.as_deref().unwrap_or("N/A"),
            finding.description,
            finding.evidence,
            finding.recommendation
        ));
    }

    report.push_str(&format!(
        "## Remediation Roadmap\n\n\
         ### Immediate (0-7 days)\n\
         Address all Critical and High severity findings immediately.\n\n\
         ### Short-term (7-30 days)\n\
         Remediate Medium severity findings and implement security headers.\n\n\
         ### Long-term (30-90 days)\n\
         Address Low severity findings and implement a continuous monitoring program.\n\n\
         ---\n\n\
         *Report generated by VulnScan — {} scan on {}*\n",
        scan_type, now
    ));

    report
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp",
        53 => "dns", 80 => "http", 110 => "pop3", 111 => "rpcbind",
        135 => "msrpc", 139 => "netbios", 143 => "imap", 443 => "https",
        445 => "smb", 993 => "imaps", 995 => "pop3s", 1433 => "mssql",
        1723 => "pptp", 3306 => "mysql", 3389 => "rdp", 5432 => "postgresql",
        5900 => "vnc", 6379 => "redis", 8080 => "http-alt", 8443 => "https-alt",
        8888 => "http-alt", 9200 => "elasticsearch", 11211 => "memcached",
        27017 => "mongodb", 5984 => "couchdb", 4444 => "metasploit",
        5555 => "adb", _ => "unknown",
    }
}

fn port_severity(port: u16) -> Severity {
    match port {
        23 | 21 | 4444 | 5555 => Severity::Critical,
        135 | 139 | 445 | 3389 | 5900 | 6379 | 9200 | 27017 | 11211 => Severity::High,
        25 | 53 | 110 | 111 | 143 | 1723 | 3306 | 5432 | 5984 => Severity::Medium,
        80 | 8080 | 8888 => Severity::Low,
        _ => Severity::Info,
    }
}

fn port_recommendation(port: &u16) -> String {
    match port {
        21 => "Disable FTP. Use SFTP or SCP instead.".to_string(),
        22 => "Restrict SSH access to specific IPs. Use key-based auth only.".to_string(),
        23 => "Disable Telnet immediately. Use SSH.".to_string(),
        80 | 8080 | 8888 => "Redirect HTTP to HTTPS. Remove default pages.".to_string(),
        3389 => "Restrict RDP to VPN. Enable NLA. Use strong passwords.".to_string(),
        6379 => "Enable Redis authentication. Bind to localhost only.".to_string(),
        27017 => "Enable MongoDB authentication. Bind to localhost or VPN.".to_string(),
        9200 => "Enable Elasticsearch security features. Restrict network access.".to_string(),
        _ => format!("Close port {} if not required, or restrict via firewall.", port),
    }
}

fn service_cves(port: u16) -> Option<Vec<String>> {
    match port {
        21 => Some(vec!["CVE-2010-4221".to_string(), "CVE-2011-1137".to_string()]),
        22 => Some(vec!["CVE-2023-38408".to_string()]),
        6379 => Some(vec!["CVE-2022-0543".to_string(), "CVE-2023-28425".to_string()]),
        27017 => Some(vec!["CVE-2019-2386".to_string()]),
        9200 => Some(vec!["CVE-2021-22145".to_string()]),
        _ => None,
    }
}

fn path_cves(path: &str) -> Option<Vec<String>> {
    if path.contains(".env") {
        Some(vec!["CWE-312".to_string(), "CWE-538".to_string()])
    } else if path.contains(".git") {
        Some(vec!["CWE-538".to_string()])
    } else {
        None
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let state = AppState {
        scans: Arc::new(Mutex::new(HashMap::new())),
        config: Arc::new(Mutex::new(AIConfig::default())),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/config", get(get_config).post(set_config))
        .route("/api/scans", get(list_scans).post(start_scan))
        .route("/api/scans/:id", get(get_scan).delete(delete_scan))
        .route("/api/scans/:id/report", get(get_report))
        .nest_service("/", ServeDir::new("frontend/dist"))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8717));
    info!("VulnScan server listening on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
