use actix_web::{web, App, HttpServer, HttpResponse, Responder, HttpRequest, cookie::Cookie};
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::sync::{Arc, Mutex}; // Mutex for thread-safe History
use std::time::{Instant, Duration};
use dashmap::{DashMap, DashSet}; // DashSet for Whitelist
use std::collections::HashMap;
use tracing::{info, warn, error};
use urlencoding::decode;
use chrono::{DateTime, Utc}; // Time handling

// --- CONFIGURATION ---
const OLLAMA_URL: &str = "http://ollama-brain:11434/api/chat";
const MODEL: &str = "llama3";
const ENTROPY_THRESHOLD: f64 = 4.8;
const MAX_REQ_PER_SEC: u32 = 10;

// --- DATA STRUCTURES ---
#[derive(Serialize, Clone)]
struct AttackLog {
    id: String,
    timestamp: String,
    ip: String,
    reason: String,
    payload: String,
    status: String, // "Blocked" or "Allowed"
}

struct AppState {
    signatures: Vec<Regex>,
    honeypots: Vec<String>,
    rate_limit: DashMap<String, (Instant, u32)>,
    // NEW: Whitelist (User said "Yes")
    allowed_ips: DashSet<String>,
    // NEW: History Log (Thread-safe list)
    history: Mutex<Vec<AttackLog>>,
}

#[derive(Serialize, Deserialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<Message>,
    stream: bool,
}

#[derive(Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: Message,
}

// --- UTILS ---
fn calculate_entropy(payload: &str) -> f64 {
    if payload.is_empty() { return 0.0; }
    let mut counts = HashMap::new();
    for c in payload.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = payload.len() as f64;
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

fn normalize_payload(payload: &str) -> String {
    let decoded = decode(payload).unwrap_or_else(|_| payload.into());
    decoded.to_lowercase()
}

// --- HELPER: LOGGING ATTACK ---
fn log_attack(data: &Arc<AppState>, ip: &str, reason: &str, payload: &str) {
    let mut history = data.history.lock().unwrap();
    let log = AttackLog {
        id: uuid::Uuid::new_v4().to_string(), // Need uuid crate? Or just random.
        // Let's use simple random ID to avoid adding another crate dependency if possible,
        // but for now, let's just use timestamp as ID part.
        timestamp: Utc::now().to_rfc3339(),
        ip: ip.to_string(),
        reason: reason.to_string(),
        payload: payload.chars().take(100).collect(), // Truncate long payloads
        status: "Blocked".to_string(),
    };
    // Keep only last 100 logs to save memory
    if history.len() > 100 { history.remove(0); }
    history.push(log);
}

// --- LAYER 2: AI SCAN ---
async fn scan_with_ai(payload: String) -> bool {
    if payload.len() < 15 { return false; }
    let client = reqwest::Client::new();
    let system_prompt = "You are a Cyber Defense AI. Your ONLY job is to detect malicious intent. If malicious, return strictly JSON: {\"malicious\": true}.";

    let request_body = OllamaRequest {
        model: MODEL.to_string(),
        stream: false,
        messages: vec![
            Message { role: "system".to_string(), content: system_prompt.to_string() },
            Message { role: "user".to_string(), content: payload },
        ],
    };

    let result = tokio::time::timeout(Duration::from_secs(2), 
        client.post(OLLAMA_URL).json(&request_body).send()
    ).await;

    match result {
        Ok(Ok(resp)) => {
            if let Ok(json) = resp.json::<OllamaResponse>().await {
                let content = json.message.content.to_lowercase();
                return content.contains("true") || content.contains("malicious");
            }
        }
        Ok(Err(e)) => error!("AI Error: {}", e),
        Err(_) => warn!("AI Timeout"),
    }
    false
}

// --- FIREWALL ENGINE ---
async fn inspect_request(req: &HttpRequest, body: &str, data: &Arc<AppState>) -> Option<HttpResponse> {
    let ip = req.peer_addr().map(|a| a.ip().to_string()).unwrap_or("unknown".to_string());

    // 0. WHITELIST CHECK (The "Yes" Button)
    if data.allowed_ips.contains(&ip) {
        return None; // Skip all checks!
    }

    let clean_body = normalize_payload(body);

    // 1. HONEYPOT
    if data.honeypots.iter().any(|h| req.path().contains(h)) {
        log_attack(data, &ip, "Honeypot Trap", req.path());
        return Some(HttpResponse::Forbidden().body("Access Denied (Trap)"));
    }

    // 2. RATE LIMIT
    let mut entry = data.rate_limit.entry(ip.clone()).or_insert((Instant::now(), 0));
    if entry.0.elapsed().as_secs() > 1 { *entry = (Instant::now(), 0); }
    entry.1 += 1;
    if entry.1 > MAX_REQ_PER_SEC {
        // Don't log rate limits to history (too noisy)
        return Some(HttpResponse::TooManyRequests().body("Slow Down"));
    }

    // 3. MATH CHALLENGE
    if let Some(cookie) = req.cookie("aegis_token") {
        if cookie.value() != "15" {
             return Some(HttpResponse::Ok().content_type("text/html").body(include_str!("../static/challenge.html")));
        }
    } else {
         return Some(HttpResponse::Ok().content_type("text/html").body(include_str!("../static/challenge.html")));
    }

    // 4. REGEX
    for regex in &data.signatures {
        if regex.is_match(&clean_body) {
            log_attack(data, &ip, "Signature Match", &clean_body);
            return Some(HttpResponse::Forbidden().body("Malicious Payload"));
        }
    }

    // 5. ENTROPY
    if body.len() > 50 && calculate_entropy(body) > ENTROPY_THRESHOLD {
        log_attack(data, &ip, "High Entropy", "Encrypted Data");
        return Some(HttpResponse::Forbidden().body("Suspicious Payload"));
    }

    // 6. AI
    if scan_with_ai(clean_body.clone()).await {
        log_attack(data, &ip, "AI Detection", &clean_body);
        return Some(HttpResponse::Forbidden().body("AI Blocked Request"));
    }

    None
}

// --- ADMIN API ---
// GET /api/history -> Returns JSON list of attacks
async fn get_history(data: web::Data<Arc<AppState>>) -> impl Responder {
    let history = data.history.lock().unwrap();
    HttpResponse::Ok().json(&*history)
}

// POST /api/allow -> Whitelists an IP
#[derive(Deserialize)]
struct AllowRequest { ip: String }
async fn allow_ip(req: web::Json<AllowRequest>, data: web::Data<Arc<AppState>>) -> impl Responder {
    data.allowed_ips.insert(req.ip.clone());
    info!("Admin allowed IP: {}", req.ip);
    HttpResponse::Ok().json("IP Allowed")
}

// --- HANDLERS ---
async fn index(req: HttpRequest, data: web::Data<Arc<AppState>>, body: String) -> impl Responder {
    if let Some(block) = inspect_request(&req, &body, &data).await { return block; }
    HttpResponse::Ok().body("✅ ACCESS GRANTED")
}

async fn admin_panel() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(include_str!("../static/admin.html"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    info!("🛡️ DiamondShield Starting...");

    let state = Arc::new(AppState {
        signatures: vec![
            Regex::new(r"union\s+select").unwrap(),
            Regex::new(r"<script>").unwrap(),
            Regex::new(r"(\.\./|/etc/passwd)").unwrap(),
            Regex::new(r"(;|\|)\s*(cat|whoami)").unwrap(),
        ],
        honeypots: vec!["/admin.php".to_string(), "/.env".to_string()],
        rate_limit: DashMap::new(),
        allowed_ips: DashSet::new(),
        history: Mutex::new(Vec::new()),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/admin", web::get().to(admin_panel)) // The Dashboard UI
            .route("/api/history", web::get().to(get_history)) // API
            .route("/api/allow", web::post().to(allow_ip)) // API
            .route("/", web::get().to(index))
            .route("/", web::post().to(index))
            .service(actix_files::Files::new("/static", "./static"))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
