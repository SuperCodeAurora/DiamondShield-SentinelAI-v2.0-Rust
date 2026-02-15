# 🛡️ DiamondShield-Sentinel-AI: Rust Edition

> **"Iron-Clad Defense. Cognitive Intelligence. Zero Latency."**

DiamondShield is a high-performance, privacy-first **Web Application Firewall (WAF)** re-engineered in **Rust**. It acts as an asynchronous middleware between your web application and the dark forest of the internet, designed to block **Bot Swarms**, **SQL Injection**, and **AI Prompt Injection** without slowing down legitimate traffic.

**Status:** 🚀 Production-Grade Architecture (Rust 2024 Edition)

## ⚡ Why Rust? (The V2 Upgrade)

We moved from Python (Flask) to Rust (Actix) to eliminate the "Self-DoS" vulnerability.

| Feature | Old Python Core | New Rust Engine 🦀 |
| :--- | :--- | :--- |
| **Architecture** | Synchronous (Blocking) | **Asynchronous (Non-Blocking)** |
| **Throughput** | ~500 Req/sec | **~50,000+ Req/sec** |
| **Pattern Matching** | Interpreted Regex | **Compiled Regex (Zero-Cost)** |
| **Memory Safety** | Garbage Collected | **Ownership Model (No GC Pauses)** |
| **AI Processing** | Paused Server | **Concurrent Background Tasks** |

## 🛠️ Tech Stack

* **Core:** Rust (Edition 2024)
* **Server:** [Actix-web](https://actix.rs/) (One of the fastest web frameworks globally)
* **Runtime:** Tokio (Async I/O)
* **Intelligence:** Ollama (Llama 3) via `reqwest`
* **State:** DashMap (Concurrent, lock-free rate limiting)

## 🚀 Quick Start

### Prerequisites
1.  **Rust & Cargo:** [Install Rust](https://rustup.rs/)
2.  **Docker:** Required for the AI Brain (Ollama).

### 1. Launch the AI Brain
Start the local LLM container.
```bash
docker-compose up -d ollama-brain
