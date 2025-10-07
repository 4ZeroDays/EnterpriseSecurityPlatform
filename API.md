Cloud Deployment
AWS
See AWS_DEPLOYMENT.md
Azure
See AZURE_DEPLOYMENT.md
Kubernetes
See k8s/README.md

### **docs/API.md:**
```markdown
# API Documentation

## Authentication

All endpoints require JWT token:
```bash
# Get token
POST /auth/token
{
  "user_id": "analyst-1",
  "permissions": ["read", "analyze"]
}

# Response
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 86400
}
Threat Analysis
Analyze Log
bashPOST /api/v1/threats/analyze
Authorization: Bearer {token}

{
  "log_data": "SELECT * FROM users WHERE 1=1",
  "source_ip": "10.0.0.1"
}

# Response
{
  "threat_id": "abc123",
  "risk_score": 92.5,
  "threat_type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "confidence": 0.94,
  "matched_rules": ["SQL_INJECTION"],
  "recommendations": [...]
}
Get Threat Details
bashGET /api/v1/threats/{threat_id}
List Threats
bashGET /api/v1/threats/?limit=10&offset=0
Rules Management
Create Rule
bashPOST /api/v1/rules
Authorization: Bearer {admin_token}

{
  "name": "Custom SQL Injection",
  "pattern": "UNION.*SELECT",
  "severity": "critical",
  "enabled": true
}
