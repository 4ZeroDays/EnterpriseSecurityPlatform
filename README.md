# 🛡️ Enterprise Security Platform

> **Production-grade threat detection platform processing 10,000+ logs/second with ML-powered analysis**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[🎥 Live Demo](https://youtu.be/n2KPhKYm2jc?si=MqQISujQT_Stuqx9) | [📊 Dashboard](https://enterprise-security-platform.vercel.app/)
## 📖 Documentation
- [Architecture Guide](ARCHITECTURE.md) — System design details  
- [Deployment Guide](DEPLOYMENT.md) — Production deployment  
- [ML Models](ML_MODELS.md) — Model training and evaluation



---

## 🎯 What This Is

An **enterprise-grade security operations platform** that detects threats in real-time using machine learning and rule-based analysis. Built with microservices architecture for scalability and production deployment.

**Use Cases:**
- Security Operations Center (SOC) monitoring
- Threat intelligence and incident response
- Compliance monitoring (PCI-DSS, SOC2)
- Cloud security event analysis

---

## ✨ Key Features

- **🤖 ML-Powered Detection** - IsolationForest + RandomForest models (92% accuracy)
- **⚡ High Performance** - Processes 10,000+ logs/second with <150ms latency
- **📊 Real-Time Dashboard** - Live threat monitoring with Streamlit
- **🔌 Multiple Ingestion Sources** - HTTP, Syslog, Kafka, File watching, Packet capture
- **📈 Full Observability** - Prometheus metrics, Grafana dashboards
- **🐳 Production Ready** - Docker Compose, health checks, auto-scaling

---

## 🎬 Quick Demo

![Dashboard Overview](https://enterprise-security-platform.vercel.app/)

### Live Threat Detection
```bash
# Submit a SQL injection attempt
curl -X POST "https://api.your-demo.com/api/v1/threats/analyze" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"log_data": "SELECT * FROM users WHERE id=1 OR 1=1--", "source_ip": "10.0.0.1"}'

# Response (92.5 risk score - CRITICAL)
{
  "threat_id": "abc123",
  "risk_score": 92.5,
  "threat_type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "confidence": 0.94
}
```

---

## 🏗️ Architecture

```
┌──────────────┐    ┌───────────────┐    ┌──────────────┐
│  Ingestion   │───→│ Redis Queue   │───→│  Detection   │
│   Service    │    │  (10K/sec)    │    │    Engine    │
│              │    │               │    │  (ML + Rules)│
└──────────────┘    └───────────────┘    └──────────────┘
  ↓ Multiple                                      ↓
  Sources:                                   ┌──────────────┐
  • HTTP API                                 │ PostgreSQL   │
  • Syslog                                   │  (Storage)   │
  • Kafka                                    └──────────────┘
  • File Watch                                      ↓
  • PCAP                                     ┌──────────────┐
                                             │  Dashboard   │
                                             │  (Streamlit) │
                                             └──────────────┘
```

### Tech Stack
- **Backend:** FastAPI, Python 3.11+
- **ML:** scikit-learn (IsolationForest, RandomForest)
- **Queue:** Redis (batching, caching)
- **Database:** PostgreSQL (threat storage)
- **Monitoring:** Prometheus, Grafana
- **Ingestion:** Scapy, Kafka, Syslog
- **Frontend:** Streamlit with Plotly

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- Redis
- PostgreSQL

### 1. Clone & Setup
```bash
git clone https://github.com/Shaid-T/Enterprise-Security-Platform.git
cd Enterprise-Security-Platform

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start Services
```bash
# Start infrastructure
docker-compose up -d redis postgres

# Initialize database
psql -h localhost -U threat_user -d security_platform -f init-db.sql

# Start API Gateway
uvicorn services.fastapi_app:app --reload --port 8000 &

# Start Detection Service
python services/detection_service.py &

# Start Ingestion Service
uvicorn services.ingestion_service:app --reload --port 9000 &

# Start Dashboard
npm run dev 


## 📊 Performance Benchmarks

| Metric | Result | Target |
|--------|--------|--------|
| **Throughput** | 750 req/sec | 500+ |
| **Detection Latency (p95)** | 145ms | <200ms |
| **Ingestion Rate** | 10,000 logs/sec | 5,000+ |
| **ML Accuracy** | 92.3% | >90% |
| **Queue Processing** | 1,200 jobs/sec | 1,000+ |

*Tested on: 4 vCPU, 8GB RAM*

---

## 🎯 Detection Capabilities

### Threat Types Detected
- **SQL Injection** - Pattern matching + ML anomaly detection
- **Cross-Site Scripting (XSS)** - Script tag and event handler detection
- **Command Injection** - Shell command pattern analysis
- **Path Traversal** - Directory traversal attempt detection
- **Brute Force** - Failed login pattern recognition
- **Malware Signatures** - Code execution pattern matching
- **LDAP Injection** - LDAP query manipulation detection

### Detection Rules
- 8 built-in rules with configurable severity
- Custom rule support via API
- ML-based anomaly detection for zero-day threats
- Confidence scoring (0-1 scale)

---

## 📈 Real-World Usage

### Example: SOC Monitoring
```python
# Ingest 10,000 logs from various sources
POST /ingest/http         # HTTP API
UDP  5140                 # Syslog
      /logs/*.log         # File watcher
      kafka://logs        # Kafka consumer

# Detection Engine processes in parallel
# Critical threats trigger immediate alerts
# Dashboard shows real-time statistics
```

### Example: Incident Response
```python
# Query historical threats
GET /api/v1/threats/?severity=CRITICAL&hours=24

# Export for forensics
GET /api/v1/threats/export?format=csv

# Block attacking IPs
POST /api/v1/blocks {"ip": "10.0.0.50"}
```

---

## 🔧 Configuration

### Environment Variables
```bash
# Redis
REDIS_URL=redis://localhost:6379
REDIS_MAX_CONNECTIONS=100

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/security_platform

# Detection
ALERT_THRESHOLD=70.0
ML_WEIGHT_ISOLATION=0.5
ML_WEIGHT_RANDOM_FOREST=0.5

# Ingestion
BATCH_SIZE=100
BATCH_TIMEOUT_MS=500
```

### Scaling
```yaml
# Scale detection workers
docker-compose up -d --scale detection-service=5

# Adjust queue batch size
BATCH_SIZE=200  # Process 200 logs per batch
```

---

## 🧪 Testing

### Run Tests
```bash
# Unit tests
pytest tests/ -v --cov

# Load testing (Apache Bench)
ab -n 1000 -c 50 \
  -H "Authorization: Bearer $TOKEN" \
  -p payload.json \
  http://localhost:8000/api/v1/threats/analyze

# Integration tests
pytest tests/integration/ -v
```

### Generate Test Data
```bash
# Submit 1000 test threats
python scripts/generate_test_threats.py --count 1000
```

---

## 📚 Documentation

- [API Documentation](http://localhost:8000/docs) - Interactive API docs
- [Architecture Guide](ARCHITECTURE.md) - System design details
- [Deployment Guide](DEPLOYMENT.md) - Production deployment
- [ML Models](ML_MODELS.md) - Model training and evaluation

---

## 🚢 Deployment

### Docker Compose (Recommended)
```bash
docker-compose up -d
```

### Kubernetes
```bash
kubectl apply -f k8s/
```

### Manual Deployment
See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

---

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.



## 🙏 Acknowledgments

Built as part of the Advanced Security Infrastructure Roadmap (Phase 6)




## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/Shaid-T/Enterprise-Security-Platform)
![GitHub forks](https://img.shields.io/github/forks/Shaid-T/Enterprise-Security-Platform)
![GitHub issues](https://img.shields.io/github/issues/Shaid-T/Enterprise-Security-Platform)
![GitHub pull requests](https://img.shields.io/github/issues-pr/Shaid-T/Enterprise-Security-Platform)

---

<div align="center">
  <p>⭐ Star this repo if you find it useful!</p>
  <p>Built with ❤️ for the security community</p>
</div>

