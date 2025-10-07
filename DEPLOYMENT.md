# Deployment Guide

## Quick Deploy (Docker Compose)
```bash
# 1. Clone repo
git clone https://github.com/Shaid-T/Enterprise-Security-Platform.git
cd Enterprise-Security-Platform

# 2. Start services
docker-compose up -d

# 3. Access
# Dashboard: http://localhost:8501
# API: http://localhost:8000/docs
Production Deployment
Prerequisites

Python 3.11+
Redis
PostgreSQL
4GB RAM minimum

Step-by-Step

Database Setup

bash# Create database
createdb security_platform

# Initialize schema
psql -d security_platform -f init-db.sql

Environment Variables

bashexport DATABASE_URL="postgresql://user:pass@localhost:5432/security_platform"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="your-secret-key"

Start Services

bash# API Gateway
uvicorn services.fastapi_app:app --host 0.0.0.0 --port 8000 &

# Detection Service (3 workers)
for i in {1..3}; do
  python services/detection_service.py &
done

# Ingestion Service
uvicorn services.ingestion_service:app --host 0.0.0.0 --port 9000 &

# Dashboard
npm run dev 


