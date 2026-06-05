# Kerberos V5 Protocol Implementation

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-AES--128-red.svg)

A simplified, from-scratch implementation of the Kerberos V5 authentication protocol based on [RFC 1510](https://datatracker.ietf.org/doc/html/rfc1510). This project demonstrates the core mechanics of symmetric-key cryptography, ticket-granting systems, and secure network communication using Python's `socket` and `cryptography` libraries.

---

## 📑 Table of Contents
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [Usage (How to Run)](#-usage-how-to-run)
- [Contributors](#-contributors)

---

## ✨ Features
* **Full Kerberos Flow:** Implements the 3-phase authentication process (AS Exchange, TGS Exchange, AP Exchange).
* **Robust Cryptography:** Uses AES-128 in CBC mode (via the `Fernet` module) with SHA-256 for key derivation to ensure data confidentiality and integrity.
* **Replay Attack Prevention:** Implements timestamp-based authenticators.
* **JSON Serialization:** Uses JSON over TCP for efficient, human-readable payload parsing and debugging.
* **Threaded KDC:** The Key Distribution Center can handle multiple client requests concurrently.

---

## 🏛 System Architecture

The system mimics a distributed network environment with three main entities:

1. **KDC (Key Distribution Center) - Port 88:** * Contains the **Authentication Server (AS)** to verify client identities and issue Ticket-Granting Tickets (TGT).
   * Contains the **Ticket-Granting Server (TGS)** to issue Service Tickets.
2. **Application Server - Port 8000:** The target service that the client wishes to access (e.g., a mock File Server).
3. **Client:** The end-user application that orchestrates the credential cache and manages the requests.

---

## 📂 Project Structure

```text
kerberos-python/
├── core/                   # Shared network and cryptography modules
│   ├── crypto.py           # AES-128 encryption/decryption wrappers
│   ├── network.py          # TCP Socket utilities for JSON data
│   └── messages.py         # Standardized protocol constants
├── kdc/                    # Key Distribution Center
│   ├── kdc_server.py       # Main KDC process (Listens on port 88)
│   ├── as_handler.py       # Authentication Server logic
│   ├── tgs_handler.py      # Ticket-Granting Server logic
│   └── database.db         # SQLite storage for Master Keys
├── client/                 # Client Application
│   ├── client_app.py       # User CLI to initiate login
│   └── credential_cache.py # In-memory storage for TGT and Session Keys
├── app_server/             # Target Service
│   └── service_server.py   # Application Server (Listens on port 8000)
├── requirements.txt        # Project dependencies
└── README.md               # Project documentation