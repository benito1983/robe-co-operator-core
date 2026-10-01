# RoBe Co-Operator - Central Composition Root

This repository demonstrates the core orchestration and architectural pattern of the **RoBe Co-Operator** platform, a highly secure, modular Fullstack ecosystem.

## 🏗️ Architecture Overview
The platform is built on an "Offline-First" and "Secure-by-Default" philosophy using **FastAPI** and **PostgreSQL**. It decouples specific domain business logic into independent backend modules.

### Core Security & Infrastructure Features shown here:
* **Sandboxed Code Execution:** Secure runtime utilizing a custom integration of RestrictedPython (with JavaScript deliberately blocked for maximum security).
* **Proactive Security Middleware:** Multi-layered defense-in-depth layout including custom Rate-Limiting, SentinelBan (automated attacker blacklisting), and strict security headers.
* **Central Composition Root:** Efficient dynamic lifecycle handling (`lifespan`), background embedding-model warmups for neural search, and dynamic skill registration.
* **Unified Error & Validation Overrides:** Gracefully replaces non-serializable floats (NaN/Infinity) with safe representations to eliminate leaky 500 server errors on malformed payloads.

## 💻 Tech Stack
* Python 3.11+
* FastAPI / Starlette
* Pydantic v2
