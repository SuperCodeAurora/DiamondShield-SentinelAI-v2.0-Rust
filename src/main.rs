use actix_web::{web, App, HttpServer, HttpResponse, Responder, HttpRequest, cookie::Key};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::sync::Arc;
use std::time::{Instant, Duration};
use dashmap::{DashMap, DashSet};
use std::collections::HashMap;
use tracing::{info, warn, error};
use urlencoding::decode;
use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, Row};

// --- CONFIGURATION ---
const OLLAMA_URL: &str = "http://ollama-brain:11434/api/chat";
const MODEL: &str = "llama3";
const ENTROPY_THRESHOLD: f64 = 4.8;
const MAX_REQ_PER_SEC: u32 = 10;
const DATABASE_URL: &str = "sqlite://diamond.db?mode=rwc";
// CHANGE THIS PASSWORD!
const ADMIN_PASS: &str = "diamond_admin_2026"; 

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

#[derive(Serialize, sqlx::FromRow)]
struct StatPoint {
    hour: String,
    count: i64,
}

struct AppState {
    signatures: Vec<Regex>,
    honeypots: Vec<String>,
    rate_limit: DashMap<String, (Instant, u32)>,
    allowed_ips: DashSet<String>,
    db: SqlitePool,
}

#[derive(Serialize, Deserialize)]
struct OllamaRequest { model: String, messages: Vec<Message>, stream: bool }
#[derive(Serialize, Deserialize)]
struct Message { role: String, content: String }
#[derive(Deserialize)]
struct OllamaResponse { message: Message }

// --- UTILS ---
fn calculate_entropy(payload: &str) -> f64 {
    if payload.is_empty() { return 0.0; }
    let mut counts = HashMap::new();
    for c in payload.chars() { *counts.entry(c).or_insert(0) += 1; }
    let len = payload.len() as f64;
    counts.values().fold(0.0, |acc, &count| { let p = count as f64 / len; acc - p * p.log2() })
}

fn normalize_payload(payload: &str) -> String {
    let decoded = decode(payload).unwrap_or_else(|_| payload.into());
    decoded.to_lowercase()
}

// --- DATABASE LOGGING ---
async fn log_attack(db: &SqlitePool, ip: &str, reason: &str, payload: &str) {
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();
    let safe_payload: String = payload.chars().take(200).collect();
    let _ = sqlx::query("INSERT INTO attacks (id, timestamp, ip, reason, payload, status) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(id).bind(timestamp).bind(ip).bind(reason).bind(safe_payload).bind("Blocked")
        .execute(db).await;
}

// --- AI SCANNER ---
async fn scan_with_ai(payload: String) -> bool {
    if payload.len() < 15 { return false; }
    let client = reqwest::Client::new();
    let body = OllamaRequest {
        model: MODEL.to_string(),
        stream: false,
        messages: vec![
            Message { role: "system".to_string(), content: "You are a Cyber Defense AI. Detect malicious intent. Return JSON: {\"malicious\": true}.".to_string() },
            Message { role: "user".to_string(), content: payload },
        ],
    };
    if let Ok(Ok(resp)) = tokio::time::timeout(Duration::from_secs(2), client.post(OLLAMA_URL).json(&body).send()).await {
        if let Ok(json) = resp.json::<OllamaResponse>().await {
            return json.message.content.to_lowercase().contains("true");
        }
    }
    false
}

// --- FIREWALL LOGIC ---
async fn inspect_request(req: &HttpRequest, body: &str, data: &Arc<AppState>) -> Option<HttpResponse> {
    let ip = req.peer_addr().map(|a| a.ip().to_string()).unwrap_or("unknown".to_string());

    if data.allowed_ips.contains(&ip) { return None; } // Whitelist

    let clean_body = normalize_payload(body);

    // 1. Honeypot
    if data.honeypots.iter().any(|h| req.path().contains(h)) {
        log_attack(&data.db, &ip, "Honeypot Trap", req.path()).await;
        return Some(HttpResponse::Forbidden().body("Access Denied (Trap)"));
    }
    // 2. Rate Limit
    let mut entry = data.rate_limit.entry(ip.clone()).or_insert((Instant::now(), 0));
    if entry.0.elapsed().as_secs() > 1 { *entry = (Instant::now(), 0); }
    entry.1 += 1;
    if entry.1 > MAX_REQ_PER_SEC { return Some(HttpResponse::TooManyRequests().body("Slow Down")); }

    // 3. Math Challenge
    if req.cookie("aegis_token").map(|c| c.value().to_string()).unwrap_or_default() != "15" {
        return Some(HttpResponse::Ok().content_type("text/html").body(include_str!("../static/challenge.html")));
    }

    // 4. Regex
    for regex in &data.signatures {
        if regex.is_match(&clean_body) {
            log_attack(&data.db, &ip, "Signature Match", &clean_body).await;
            return Some(HttpResponse::Forbidden().body("Malicious Payload"));
        }
    }
    // 5. Entropy
    if body.len() > 50 && calculate_entropy(body) > ENTROPY_THRESHOLD {
        log_attack(&data.db, &ip, "High Entropy", "Encrypted").await;
        return Some(HttpResponse::Forbidden().body("Suspicious Payload"));
    }
    // 6. AI
    if scan_with_ai(clean_body).await {
        log_attack(&data.db, &ip, "AI Detection", &clean_body).await;
        return Some(HttpResponse::Forbidden().body("AI Blocked"));
    }
    None
}

// --- AUTH & API HANDLERS ---
#[derive(Deserialize)]
struct LoginRequest { password: String }
async fn login(req: web::Json<LoginRequest>, session: Session) -> impl Responder {
    if req.password == ADMIN_PASS {
        session.insert("user", "admin").unwrap();
        HttpResponse::Ok().json("Logged In")
    } else {
        HttpResponse::Unauthorized().body("Wrong Password")
    }
}

async fn logout(session: Session) -> impl Responder {
    session.purge();
    HttpResponse::Ok().body("Logged out")
}

// GET /api/stats (For The War Room)
async fn get_stats(data: web::Data<Arc<AppState>>, session: Session) -> impl Responder {
    if session.get::<String>("user").unwrap_or(None).is_none() { return HttpResponse::Unauthorized().finish(); }
    
    // Aggregate attacks by hour for the last 24h
    let rows = sqlx::query_as::<_, StatPoint>(
        "SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, COUNT(*) as count 
         FROM attacks GROUP BY hour ORDER BY hour DESC LIMIT 24"
    ).fetch_all(&data.db).await.unwrap_or(vec![]);
    
    HttpResponse::Ok().json(rows)
}

async fn get_history(data: web::Data<Arc<AppState>>, session: Session) -> impl Responder {
    if session.get::<String>("user").unwrap_or(None).is_none() { return HttpResponse::Unauthorized().finish(); }
    let rows = sqlx::query_as::<_, AttackLog>("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50").fetch_all(&data.db).await.unwrap_or(vec![]);
    HttpResponse::Ok().json(rows)
}

async fn allow_ip(req: web::Json<serde_json::Value>, data: web::Data<Arc<AppState>>, session: Session) -> impl Responder {
    if session.get::<String>("user").unwrap_or(None).is_none() { return HttpResponse::Unauthorized().finish(); }
    let ip = req["ip"].as_str().unwrap_or_default();
    data.allowed_ips.insert(ip.to_string());
    sqlx::query("UPDATE attacks SET status = 'Allowed' WHERE ip = ?").bind(ip).execute(&data.db).await.ok();
    sqlx::query("INSERT OR IGNORE INTO whitelist (ip) VALUES (?)").bind(ip).execute(&data.db).await.ok();
    HttpResponse::Ok().json("Allowed")
}

async fn admin_panel(session: Session) -> impl Responder {
    if session.get::<String>("user").unwrap_or(None).is_some() {
        HttpResponse::Ok().content_type("text/html").body(include_str!("../static/admin.html"))
    } else {
        HttpResponse::Found().append_header(("Location", "/login.html")).finish()
    }
}

async fn index(req: HttpRequest, data: web::Data<Arc<AppState>>, body: String) -> impl Responder {
    if let Some(block) = inspect_request(&req, &body, &data).await { return block; }
    HttpResponse::Ok().body("✅ ACCESS GRANTED")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();
    let db = SqlitePool::connect(DATABASE_URL).await.expect("DB Fail");
    sqlx::query("CREATE TABLE IF NOT EXISTS attacks (id TEXT PRIMARY KEY, timestamp TEXT, ip TEXT, reason TEXT, payload TEXT, status TEXT)").execute(&db).await.ok();
    sqlx::query("CREATE TABLE IF NOT EXISTS whitelist (ip TEXT PRIMARY KEY)").execute(&db).await.ok();
    
    let allowed_ips = DashSet::new();
    for row in sqlx::query_as::<_, (String,)>("SELECT ip FROM whitelist").fetch_all(&db).await.unwrap_or(vec![]) {
        allowed_ips.insert(row.0);
    }
    
    let state = Arc::new(AppState {
        signatures: vec![Regex::new(r"(?i)union\s+select").unwrap(), Regex::new(r"(?i)<script>").unwrap(), Regex::new(r"(?i)(\.\./|/etc/passwd)").unwrap()],
        honeypots: vec!["/admin.php".to_string(), "/.env".to_string()],
        rate_limit: DashMap::new(), allowed_ips, db,
    });
    
    let secret_key = Key::generate(); // Generates a random session key on restart

    info!("🛡️ DiamondShield v2.0 Online. Admin Password: {}", ADMIN_PASS);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(SessionMiddleware::new(CookieSessionStore::default(), secret_key.clone()))
            .route("/admin", web::get().to(admin_panel))
            .route("/api/login", web::post().to(login))
            .route("/api/logout", web::post().to(logout))
            .route("/api/history", web::get().to(get_history))
            .route("/api/stats", web::get().to(get_stats))
            .route("/api/allow", web::post().to(allow_ip))
            .route("/", web::get().to(index))
            .route("/", web::post().to(index))
            .service(actix_files::Files::new("/", "./static").index_file("challenge.html"))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
