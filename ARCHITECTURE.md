# Architecture Overview

## System Design

###  Architecture
┌─────────────────┐
│  Client Apps    │
│  (SIEM, SOC)    │
└────────┬────────┘
│
┌────────▼────────┐
│  API Gateway    │ ← FastAPI (Port 8000)
│  - Auth (JWT)   │
│  - Rate Limit   │
└────────┬────────┘
│
┌────────▼────────┐
│  Redis Queue    │ ← Message Broker
│  - Batching     │
│  - Caching      │
└────────┬────────┘
│
┌────────▼────────┐
│ Detection Svc   │ ← ML Analysis
│ - IsolationFor. │
│ - RandomForest  │
└────────┬────────┘
│
┌────────▼────────┐
│  PostgreSQL     │ ← Persistent Storage
│  - Threats      │
│  - Rules        │
└─────────────────┘

## Components

### API Gateway (FastAPI)
- **Port:** 8000
- **Purpose:** HTTP entry point
- **Features:** JWT auth, rate limiting, OpenAPI docs

### Detection Service (Python Worker)
- **Purpose:** Threat analysis
- **ML Models:** IsolationForest (anomaly), RandomForest (classification)
- **Rules:** 8 built-in patterns (SQL injection, XSS, etc.)

### Ingestion Service (FastAPI)
- **Port:** 9000
- **Purpose:** Multi-source log collection
- **Sources:** HTTP, Syslog, Kafka, File watching, PCAP

### Dashboard (Streamlit)
- **Port:** 8501
- **Purpose:** Real-time monitoring
- **Features:** Threat feed, analytics, system health

## Data Flow

1. Log enters via Ingestion Service
2. Validated and batched (100 logs/batch)
3. Pushed to Redis queue
4. Detection Service pulls from queue
5. ML + rule-based analysis
6. Results stored in PostgreSQL
7. Cached in Redis (24h)
8. High-severity alerts published
9. Dashboard displays real-time updates

## Scaling

- **Horizontal:** Run multiple Detection Service workers
- **Vertical:** Increase Redis/PostgreSQL resources
- **Queue:** Handles 10,000+ logs/second with batching
