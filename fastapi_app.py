from fastapi import FastAPI, Query, Depends, Request, status, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, validator, StringConstraints
from contextlib import asynccontextmanager
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
import redis.asyncio as redis
import asyncio
import json
import time
import os
import uuid
import jwt
import logging
import sys
from typing_extensions import Annotated
import subprocess
import smtplib
from email.message import EmailMessage
import ssl 
import os

logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "service": "api-gateway", "message": "%(message)s"}'
)
logger = logging.getLogger(__name__)

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.insert(0, root)

try:
    from services.detection_service import analyze, threat_db
except Exception as e:
    logger.warning(f"Detection module import failed: {e}")
    # Create mock objects for development
    class MockThreatDB:
        class Pool:
            def acquire(self):
                return self
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def execute(self, query):
                return None
            async def fetch(self, query, *args):
                return []
        pool = Pool()
    
    threat_db = MockThreatDB()
    
    def analyze_log(log_data):
        return {
            'score': 45.0,
            'threat': 'unknown',
            'severity': 'LOW',
            'confidence': 0.5
        }
        

	    
	    
def send_email(subject, body, to_email):
    from_email = os.getenv("EMAIL", "example@gmail.com")
    password = os.getenv("EMAIL_PASSWORD", "example123")
	
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = from_email
    message['To'] = to_email
    message.set_content(body)
	
    try:
        context = sll.create_Default_context()
        with smtplib.SMTP_SLL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(from_email, password)
            smtp.send_message(message)
            logger.info("SENT EMAIL SUCESSFULLY")
    except smtplib.SMTPAuthenticationError as e:
        logger.info(f"Failed to authenticate. Please check your email, password, and security settings\nError: {e}")
    except Exception as e:
        logger.info(f"Failed to send email error: {e}")
        


def ipset_create_set(set_name="blocked_ips"):
    subprocess.run(["ipset", "create", set_name, "hash:ip"], check=False)

def ipset_add(ip: str, set_name="blocked_ips"):

    subprocess.run(["ipset", "add", set_name, ip, "-exist"], check=False)

    subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", set_name, "src", "-j", "DROP"], check=False)
    logger.warning(f"ipset add {ip}")

def ipset_remove(ip: str, set_name="blocked_ips"):
    subprocess.run(["ipset", "del", set_name, ip], check=False)
    logger.info(f"ipset remove {ip}")
		

jwt_secret = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
jwt_algorithm = 'HS256'
jwt_expiration_hours = 24

redis_client = None
security = HTTPBearer()

ipset_create_set("blocked_ips")

 

app = FastAPI(
    title='Enterprise Security Platform API',
    description='Production-ready threat detection and SIEM integration platform',
    version='1.0.0',
    docs_url='/docs',
    redoc_url='/redoc'
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],
    allow_headers=["*"]
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=['localhost', '127.0.0.1', '*.yourdomain.com']
)


class ThreatAnalysisRequest(BaseModel):
    log_data: str = Field(..., description='Raw Log Data')
    source_ip: str = Field(..., description="Source IP address")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description='Additional metadata')
    
    @validator('source_ip')
    def validate_ip(cls, v):
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP format')


class ThreatResponse(BaseModel):
    threat_id: str = Field(..., description='Unique threat ID')
    risk_score: float = Field(..., ge=0, le=100, description='Risk score 0-100')
    threat_type: str = Field(..., description='Threat type')
    confidence: float = Field(..., ge=0, le=1, description='Confidence')
    severity: str = Field(..., description='Severity')
    recommendations: List[str] = Field(default_factory=list, description='Recommendations')
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DetectionRule(BaseModel):
    rule_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=100)
    pattern: str = Field(..., description="Regex or rule pattern")
    severity: Annotated[str, StringConstraints(pattern=r"^(low|medium|high|critical)$")]
    enabled: bool = Field(default=True)


class APIKeyRequest(BaseModel):
    user_id: str = Field(..., description='User ID')
    permissions: List[str] = Field(default=['read'], description='API permissions')


async def create_jwt_token(user_id: str, permissions: List[str]) -> str:
    payload = {
        "user_id": user_id,
        "permissions": permissions,
        "exp": datetime.utcnow() + timedelta(hours=jwt_expiration_hours),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm)


async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, jwt_secret, algorithms=[jwt_algorithm])
        user_id = payload.get('user_id')
        permissions = payload.get('permissions', [])
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid auth token")
        return {"user_id": user_id, "permissions": permissions}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Auth token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid auth token")
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(status_code=401, detail="Token verification failed")


async def rate_limit_check(user_data: dict = Depends(verify_jwt_token)):
    user_id = user_data['user_id']
    key = f"rate_limit:{user_id}"
    
    current = await redis_client.get(key)
    if not current:
        await redis_client.setex(key, 3600, 1)
    else:
        current = int(current)
        if current >= 1000:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        await redis_client.incr(key)
    return user_data


@app.on_event("startup")
async def startup():
    global redis_client
    try:
        redis_client = await redis.from_url("redis://localhost:6379", decode_responses=True)
        await redis_client.ping()
        logger.info("API Gateway startup - Redis connected")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        raise


@app.on_event("shutdown")
async def shutdown():
    if redis_client:
        await redis_client.close()
    logger.info("API Gateway shutdown")



@app.get("/", tags=['System'])
async def root():
    return {
        "service": "Enterprise Security Platform API Gateway",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs"
    }


@app.get("/health", tags=['System'])
async def health_check():
    import httpx
    
    redis_status = 'unhealthy'
    db_status = 'unhealthy'
    external_status = 'unhealthy'
    
    try:
        await redis_client.ping()
        redis_status = 'healthy'
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
    
    try:
        async with threat_db.pool.acquire() as conn:
            await conn.execute("SELECT 1;")
        db_status = 'healthy'
    except Exception as e:
        logger.error(f"DB health check failed: {e}")
    
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get("https://api.vendor.com/health")
            if response.status_code == 200:
                external_status = 'healthy'
            else:
                external_status = f"Unhealthy: {response.status_code}"
    except Exception as e:
        logger.error(f"External API health check failed: {e}")
    
    components = {
        "redis": redis_status,
        "database": db_status,
        "external_apis": external_status
    }
    
    overall = "healthy" if all(v == 'healthy' for v in components.values()) else 'degraded'
    
    health_status = {
        "system": "api-gateway",
        "timestamp": datetime.utcnow().isoformat(),
        "status": overall,
        "components": components
    }
    
    status_code = 200 if overall == 'healthy' else 503
    return health_status


@app.post("/auth/token", tags=['Authorization'])
async def create_api_token(request: APIKeyRequest):
    token = await create_jwt_token(request.user_id, request.permissions)
    logger.info(f"API Token created for user: {request.user_id}")
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": jwt_expiration_hours * 3600,
        "permissions": request.permissions
    }


@app.post("/api/v1/threats/analyze", response_model=ThreatResponse, tags=['Threat Detection'])
async def analyze_threat(request: ThreatAnalysisRequest, user_data: dict = Depends(rate_limit_check)):
    threat_id = str(uuid.uuid4())
    start_time = time.time()
    
    result = analyze(request.log_data)
    if result is None:
        logger.warning("No log analysis result")
        result = {}
    
    risk_score = result.get('score', 0.0)
    threat_type = result.get('threat', 'unknown')
    severity = result.get('severity', 'UNKNOWN')
    confidence = result.get('confidence', 0.0)
    
    recommendations = []
    if risk_score > 50:
        recommendations = [
            'Quarantine affected system immediately',
            'Run full antivirus scan',
            'Check for lateral movement',
            'Review user access logs'
        ]
        source_ip = result.get('source_ip')
        if source_ip:
            ipset.add(source_ip)
        
        subject = f"Risk score greater than 50 for ip: {result.get('source_ip')}"
        body = f"{result}"
        send_email(subject=subject, body=body, to_email="example@gmail.com")
        
        
    
    processing_time = time.time() - start_time
    logger.info(f"Analysis complete - ID: {threat_id}, User: {user_data['user_id']}, Risk Score: {risk_score}, Time: {processing_time:.2f}s")
    
    response = ThreatResponse(
        threat_id=threat_id,
        risk_score=risk_score,
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        recommendations=recommendations
    )
    
    await redis_client.setex(f"threat:{threat_id}", 3600, response.json())
    return response


@app.get("/api/v1/threats/{threat_id}", response_model=ThreatResponse, tags=['Threat Detection'])
async def get_threat_details(threat_id: str, user_data: dict = Depends(verify_jwt_token)):
    cached = await redis_client.get(f"threat:{threat_id}")
    if not cached:
        raise HTTPException(status_code=404, detail="Threat not found")
    return ThreatResponse.parse_raw(cached)


@app.get("/api/v1/threats/", response_model=List[ThreatResponse], tags=['Threat Detection'])
async def threat_list(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user_data: dict = Depends(verify_jwt_token)
):
    async with threat_db.pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, ip, threat, severity, score, confidence, timestamp
            FROM events
            ORDER BY timestamp DESC
            LIMIT $1 OFFSET $2
        """, limit, offset)
    
    threats = []
    for row in rows:
        threats.append(ThreatResponse(
            threat_id=str(row['id']),
            risk_score=row.get('score', 0.0),
            threat_type=row.get('threat', 'unknown'),
            severity=row.get('severity', 'N/A'),
            confidence=row.get('confidence', 0.0),
            recommendations=['Review access logs'] if row.get('score', 0) > 50 else [],
            created_at=row.get('timestamp', datetime.utcnow())
        ))
    
    return threats


@app.post("/api/v1/rules", response_model=DetectionRule, tags=["Rule Management"])
async def create_detection_rule(rule: DetectionRule, user_data: dict = Depends(rate_limit_check)):
    if "admin" not in user_data.get("permissions", []):
        raise HTTPException(status_code=403, detail="Admin permissions required")
    
    rule.rule_id = str(uuid.uuid4())
    await redis_client.setex(f"rule:{rule.rule_id}", 86400 * 30, rule.json())
    logger.info(f"Detection rule created - ID: {rule.rule_id}, User: {user_data['user_id']}")
    return rule


@app.get("/api/v1/rules", response_model=List[DetectionRule], tags=["Rule Management"])
async def list_rules(user_data: dict = Depends(verify_jwt_token)):
    keys = await redis_client.keys("rule:*")
    rules = []
    for key in keys:
        data = await redis_client.get(key)
        if data:
            rules.append(DetectionRule.parse_raw(data))
    return rules


@app.put("/api/v1/rules/{rule_id}", response_model=DetectionRule, tags=["Rule Management"])
async def update_rule(rule_id: str, rule: DetectionRule, user_data: dict = Depends(rate_limit_check)):
    if "admin" not in user_data.get("permissions", []):
        raise HTTPException(status_code=403, detail="Admin permissions required")
    
    existing = await redis_client.get(f"rule:{rule_id}")
    if not existing:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule.rule_id = rule_id
    await redis_client.setex(f"rule:{rule_id}", 86400 * 30, rule.json())
    logger.info(f"Detection rule updated - ID: {rule_id}, User: {user_data['user_id']}")
    return rule


@app.delete("/api/v1/rules/{rule_id}", tags=["Rule Management"])
async def delete_rule(rule_id: str, user_data: dict = Depends(rate_limit_check)):
    if "admin" not in user_data.get("permissions", []):
        raise HTTPException(status_code=403, detail="Admin permissions required")
    
    deleted = await redis_client.delete(f"rule:{rule_id}")
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    logger.info(f"Detection rule deleted - ID: {rule_id}, User: {user_data['user_id']}")
    return {"status": "success", "message": f"Rule {rule_id} deleted"}


@app.get("/metrics", tags=["Monitoring"], response_class=PlainTextResponse)
async def prometheus_metrics():
    """
    Prometheus metrics endpoint for Grafana monitoring
    Returns plain text format that Prometheus can scrape
    """
    metrics = """# HELP api_requests_total Total number of API requests
# TYPE api_requests_total counter
api_requests_total{method="GET",endpoint="/api/v1/threats/"} 150
api_requests_total{method="POST",endpoint="/api/v1/threats/analyze"} 1205

# HELP threat_analysis_duration_seconds Time spent analyzing threats
# TYPE threat_analysis_duration_seconds histogram
threat_analysis_duration_seconds_bucket{le="0.1"} 800
threat_analysis_duration_seconds_bucket{le="0.5"} 1150
threat_analysis_duration_seconds_bucket{le="1.0"} 1200
threat_analysis_duration_seconds_bucket{le="+Inf"} 1205
threat_analysis_duration_seconds_sum 245.5
threat_analysis_duration_seconds_count 1205
"""
    return metrics


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
