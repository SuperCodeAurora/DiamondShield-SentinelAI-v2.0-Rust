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
struct AttackLog use actix_web::{web, App, HttpServer, HttpResponse, Responder, HttpRequest, cookie::Cookie};
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::sync::Arc;
use std::time::{Instant, Duration};
use dashmap::{DashMap, DashSet};
use std::collections::HashMap;
use tracing::{info, warn, error};
use urlencoding::decode;
use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, Row}; // Database tools

// --- CONFIGURATION ---
const OLLAMA_URL: &str = "http://ollama-brain:11434/api/chat";
const MODEL: &str = "llama3";
const ENTROPY_THRESHOLD: f64 = 4.8;
const MAX_REQ_PER_SEC: u32 = 10;
const DATABASE_URL: &str = "sqlite://diamond.db?mode=rwc"; // rwc = Read/Write/Create

// --- DATA STRUCTURES ---
#[derive(Serialize, sqlx::FromRow)]
struct AttackLog {
    id: String,
    timestamp: String,
    ip: String,
    reason: String,
    payload: String,
    status: String,
}

struct AppState {
    signatures: Vec<Regex>,
    honeypots: Vec<String>,
    rate_limit: DashMap<String, (Instant, u32)>,
    allowed_ips: DashSet<String>, // RAM Cache for speed
    db: SqlitePool,               // Connection to Hard Drive
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

// --- DATABASE HELPERS ---
async fn log_attack(db: &SqlitePool, ip: &str, reason: &str, payload: &str) {
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();
    let safe_payload: String = payload.chars().take(200).collect(); // Limit size

    // Fire and forget insert
    let _ = sqlx::query("INSERT INTO attacks (id, timestamp, ip, reason, payload, status) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(timestamp)
        .bind(ip)
        .bind(reason)
        .bind(safe_payload)
        .bind("Blocked")
        .execute(db)
        .await;
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

    // 0. WHITELIST CHECK (RAM Cache - Ultra Fast)
    if data.allowed_ips.contains(&ip) {
        return None; 
    }

    let clean_body = normalize_payload(body);

    // 1. HONEYPOT
    if data.honeypots.iter().any(|h| req.path().contains(h)) {
        log_attack(&data.db, &ip, "Honeypot Trap", req.path()).await;
        return Some(HttpResponse::Forbidden().body("Access Denied (Trap)"));
    }

    // 2. RATE LIMIT
    let mut entry = data.rate_limit.entry(ip.clone()).or_insert((Instant::now(), 0));
    if entry.0.elapsed().as_secs() > 1 { *entry = (Instant::now(), 0); }
    entry.1 += 1;
    if entry.1 > MAX_REQ_PER_SEC {
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
            log_attack(&data.db, &ip, "Signature Match", &clean_body).await;
            return Some(HttpResponse::Forbidden().body("Malicious Payload"));
        }
    }

    // 5. ENTROPY
    if body.len() > 50 && calculate_entropy(body) > ENTROPY_THRESHOLD {
        log_attack(&data.db, &ip, "High Entropy", "Encrypted Data").await;
        return Some(HttpResponse::Forbidden().body("Suspicious Payload"));
    }

    // 6. AI
    if scan_with_ai(clean_body.clone()).await {
        log_attack(&data.db, &ip, "AI Detection", &clean_body).await;
        return Some(HttpResponse::Forbidden().body("AI Blocked Request"));
    }

    None
}

// --- ADMIN API ---
// GET /api/history -> Reads from Disk
async fn get_history(data: web::Data<Arc<AppState>>) -> impl Responder {
    let rows = sqlx::query_as::<_, AttackLog>("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50")
        .fetch_all(&data.db)
        .await
        .unwrap_or(vec![]);
    HttpResponse::Ok().json(rows)
}

// POST /api/allow -> Writes to Disk AND RAM
#[derive(Deserialize)]
struct AllowRequest { ip: String }
async fn allow_ip(req: web::Json<AllowRequest>, data: web::Data<Arc<AppState>>) -> impl Responder {
    // 1. Update RAM (Instant effect)
    data.allowed_ips.insert(req.ip.clone());
    
    // 2. Update Disk (Persistence)
    // We update old logs to 'Allowed' and insert into a whitelist table if we had one.
    // For now, let's just mark the logs as allowed so the dashboard updates.
    let _ = sqlx::query("UPDATE attacks SET status = 'Allowed' WHERE ip = ?")
        .bind(&req.ip)
        .execute(&data.db)
        .await;
        
    // (Optional) You could have a 'whitelist' table here to persist approvals across restarts.
    let _ = sqlx::query("INSERT OR IGNORE INTO whitelist (ip) VALUES (?)")
        .bind(&req.ip)
        .execute(&data.db)
        .await;

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
    info!("🛡️ DiamondShield Starting (With Persistence)...");

    // 1. Initialize Database
    let db = SqlitePool::connect(DATABASE_URL).await.expect("Failed to connect to DB");
    
    // 2. Create Tables if missing
    sqlx::query("CREATE TABLE IF NOT EXISTS attacks (id TEXT PRIMARY KEY, timestamp TEXT, ip TEXT, reason TEXT, payload TEXT, status TEXT)")
        .execute(&db).await.expect("Failed to create attacks table");
    
    sqlx::query("CREATE TABLE IF NOT EXISTS whitelist (ip TEXT PRIMARY KEY)")
        .execute(&db).await.expect("Failed to create whitelist table");

    // 3. Load Whitelist into RAM
    let allowed_ips = DashSet::new();
    let rows: Vec<(String,)> = sqlx::query_as("SELECT ip FROM whitelist")
        .fetch_all(&db).await.unwrap_or(vec![]);
    
    for row in rows {
        allowed_ips.insert(row.0);
    }
    info!("Loaded {} whitelisted IPs from disk.", allowed_ips.len());

    let state = Arc::new(AppState {
        signatures: vec![
            Regex::new(r"union\s+select").unwrap(),
            Regex::new(r"<script>").unwrap(),
            Regex::new(r"(\.\./|/etc/passwd)").unwrap(),
            Regex::new(r"(;|\|)\s*(cat|whoami)").unwrap(),
        ],
        honeypots: vec!["/admin.php".to_string(), "/.env".to_string()],
        rate_limit: DashMap::new(),
        allowed_ips,
        db,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/admin", web::get().to(admin_panel))
            .route("/api/history", web::get().to(get_history))
            .route("/api/allow", web::post().to(allow_ip))
            .route("/", web::get().to(index))
            .route("/", web::post().to(index))
            .service(actix_files::Files::new("/static", "./static"))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
