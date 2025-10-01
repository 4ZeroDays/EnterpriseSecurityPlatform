# Detection Service - Microservice for Threat Analysis (ML-integrated)
# Enhanced version with improvements for production readiness
import asyncio
import json
import logging
import os
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
import asyncpg
import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

# ML libraries
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import joblib
import numpy as np

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "service": "detection-engine", "message": "%(message)s"}'
)
logger = logging.getLogger(__name__)

# Configuration with validation
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/security_platform")
REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "50"))
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "5"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "20"))
QUEUE_TIMEOUT = int(os.getenv("QUEUE_TIMEOUT", "5"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
MAX_LOG_SIZE = int(os.getenv("MAX_LOG_SIZE", "100000"))  # 100KB limit
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "70.0"))

# Load ML models with error handling
def load_ml_models() -> tuple[Optional[IsolationForest], Optional[TfidfVectorizer]]:
    """Load pre-trained ML models with comprehensive error handling."""
    try:
        model_path = os.getenv("MODEL_PATH", "models")
        anomaly_model = joblib.load(f"{model_path}/anomaly_model.pkl")
        vectorizer = joblib.load(f"{model_path}/tfidf_vectorizer.pkl")
        logger.info("✅ ML models loaded successfully")
        return anomaly_model, vectorizer
    except FileNotFoundError:
        logger.warning("ML model files not found. Running in rule-based mode only.")
        return None, None
    except Exception as e:
        logger.error(f"Failed to load ML models: {e}", exc_info=True)
        return None, None

anomaly_model, vectorizer = load_ml_models()

# --------------------------
# Detection Engine
# --------------------------
class ThreatDetectionEngine:
    """Core detection engine with rule-based and ML-based analysis."""
    
    def __init__(self):
        self.rules = self._load_detection_rules()
        self.ml_enabled = anomaly_model is not None and vectorizer is not None
        self._stats = {"total_analyzed": 0, "threats_detected": 0, "ml_errors": 0}
        logger.info(f"Detection engine initialized with {len(self.rules)} rules, ML enabled={self.ml_enabled}")
    
    def _load_detection_rules(self) -> List[Dict[str, Any]]:
        """Load detection rules with enhanced patterns."""
        return [
            {
                "id": "SQL_INJECTION",
                "pattern": r"(\bunion\b.*\bselect\b|\bor\b.*=.*\bor\b|'.*--|;.*drop\b.*\btable\b|\bxp_cmdshell\b)",
                "severity": "CRITICAL",
                "score_weight": 95.0,
                "category": "injection"
            },
            {
                "id": "XSS_ATTACK",
                "pattern": r"<script[^>]*>.*?</script>|javascript:|onerror\s*=|onload\s*=|<iframe",
                "severity": "HIGH",
                "score_weight": 85.0,
                "category": "injection"
            },
            {
                "id": "PATH_TRAVERSAL",
                "pattern": r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|\\windows\\system32|%2e%2e",
                "severity": "HIGH",
                "score_weight": 80.0,
                "category": "access"
            },
            {
                "id": "COMMAND_INJECTION",
                "pattern": r"[;&|`$]\s*(cat|ls|wget|curl|nc|bash|sh|powershell)",
                "severity": "CRITICAL",
                "score_weight": 92.0,
                "category": "injection"
            },
            {
                "id": "BRUTE_FORCE",
                "pattern": r"(failed.{0,50}login|authentication.{0,50}failed|invalid.{0,50}password).{5,}",
                "severity": "MEDIUM",
                "score_weight": 65.0,
                "category": "authentication"
            },
            {
                "id": "SUSPICIOUS_USER_AGENT",
                "pattern": r"(nikto|sqlmap|nmap|masscan|metasploit|burp|acunetix|w3af)",
                "severity": "MEDIUM",
                "score_weight": 60.0,
                "category": "reconnaissance"
            },
            {
                "id": "MALWARE_SIGNATURE",
                "pattern": r"(eval\s*\(|base64_decode|exec\s*\(|system\s*\(|passthru|shell_exec)",
                "severity": "CRITICAL",
                "score_weight": 90.0,
                "category": "malware"
            },
            {
                "id": "LDAP_INJECTION",
                "pattern": r"\*\)|\(.*\||\)\(|\(\&",
                "severity": "HIGH",
                "score_weight": 83.0,
                "category": "injection"
            }
        ]
    
    async def analyze(self, log_data: str, source_ip: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze log data for threats using rules and ML."""
        start_time = datetime.utcnow()
        self._stats["total_analyzed"] += 1
        
        # Input validation
        if len(log_data) > MAX_LOG_SIZE:
            logger.warning(f"Log data exceeds size limit for IP {source_ip}")
            log_data = log_data[:MAX_LOG_SIZE]
        
        matched_rules = []
        total_score = 0.0
        log_lower = log_data.lower()
        
        # Rule-based detection with optimized matching
        for rule in self.rules:
            try:
                if re.search(rule["pattern"], log_lower, re.IGNORECASE):
                    matched_rules.append(rule)
                    total_score += rule["score_weight"]
                    logger.info(f"Rule matched: {rule['id']} for IP {source_ip}")
            except re.error as e:
                logger.error(f"Regex error in rule {rule['id']}: {e}")
        
        # ML-based anomaly detection
        ml_risk_score = 0.0
        if self.ml_enabled:
            ml_risk_score = await self._ml_anomaly_detection(log_data, source_ip)
            total_score += ml_risk_score * 0.5
        
        # Calculate final risk score (normalized to 0-100)
        risk_score = min(total_score, 100.0)
        
        # Determine threat classification
        threat_type, severity, confidence = self._classify_threat(matched_rules, risk_score)
        
        if threat_type != "BENIGN":
            self._stats["threats_detected"] += 1
        
        # Generate contextual recommendations
        recommendations = self._generate_recommendations(risk_score, matched_rules, metadata)
        
        processing_time = (datetime.utcnow() - start_time).total_seconds()
        
        return {
            "risk_score": round(risk_score, 2),
            "threat_type": threat_type,
            "severity": severity,
            "confidence": round(confidence, 3),
            "matched_rules": [r["id"] for r in matched_rules],
            "rule_categories": list(set(r["category"] for r in matched_rules)),
            "recommendations": recommendations,
            "processing_time_ms": round(processing_time * 1000, 2),
            "analyzed_at": start_time.isoformat(),
            "ml_enabled": self.ml_enabled
        }
    
    async def _ml_anomaly_detection(self, log_data: str, source_ip: str) -> float:
        """Perform ML-based anomaly detection."""
        try:
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            X = await loop.run_in_executor(None, vectorizer.transform, [log_data])
            anomaly_score = await loop.run_in_executor(None, anomaly_model.decision_function, X)
            
            # Convert to 0-100 risk scale (lower anomaly_score = more anomalous)
            ml_risk_score = max(min((1 - anomaly_score[0]) * 100, 100.0), 0.0)
            logger.info(f"ML anomaly score={ml_risk_score:.2f} for IP {source_ip}")
            return ml_risk_score
        except Exception as e:
            self._stats["ml_errors"] += 1
            logger.warning(f"ML analysis failed for IP {source_ip}: {e}")
            return 0.0
    
    def _classify_threat(self, matched_rules: List[Dict], risk_score: float) -> tuple[str, str, float]:
        """Classify threat type, severity, and confidence."""
        if not matched_rules:
            return "BENIGN", "LOW", 0.15
        
        # Get highest severity rule
        highest_rule = max(matched_rules, key=lambda r: r["score_weight"])
        threat_type = highest_rule["id"]
        severity = highest_rule["severity"]
        
        # Calculate confidence based on multiple factors
        base_confidence = 0.75
        rule_count_boost = min(0.05 * len(matched_rules), 0.15)
        score_boost = min((risk_score / 100) * 0.10, 0.10)
        confidence = min(base_confidence + rule_count_boost + score_boost, 0.99)
        
        return threat_type, severity, confidence
    
    def _generate_recommendations(self, risk_score: float, matched_rules: List[Dict], metadata: Dict[str, Any]) -> List[str]:
        """Generate contextual security recommendations."""
        recommendations = []
        
        # Risk-based recommendations
        if risk_score >= 80:
            recommendations.extend([
                "🚨 CRITICAL: Initiate incident response protocol",
                "🔒 Block source IP at perimeter firewall immediately",
                "🔐 Force password reset for potentially affected accounts",
                "🔍 Investigate lateral movement and data exfiltration",
                "📊 Preserve forensic evidence (logs, memory dumps)"
            ])
        elif risk_score >= 60:
            recommendations.extend([
                "⚠️ HIGH: Escalate to security operations center (SOC)",
                "👁️ Enable enhanced monitoring for source IP",
                "🔍 Review associated user sessions and access logs",
                "📧 Alert security team with threat context"
            ])
        elif risk_score >= 40:
            recommendations.extend([
                "📊 MEDIUM: Log event for trend analysis",
                "👁️ Monitor for pattern escalation over 24h window",
                "🔍 Correlate with SIEM for related events"
            ])
        else:
            recommendations.append("✅ LOW: Continue normal monitoring")
        
        # Rule-specific recommendations
        rule_recs = {
            "SQL_INJECTION": "🛡️ Implement parameterized queries and ORM",
            "XSS_ATTACK": "🧹 Deploy content security policy (CSP) and input sanitization",
            "COMMAND_INJECTION": "🔒 Use allowlists for command execution and input validation",
            "BRUTE_FORCE": "🔐 Enable rate limiting, CAPTCHA, and account lockout policies",
            "PATH_TRAVERSAL": "📁 Validate file paths and use chroot jails",
            "LDAP_INJECTION": "🔐 Use LDAP encoding libraries and input validation",
            "MALWARE_SIGNATURE": "🦠 Scan for malware and review code execution paths"
        }
        
        for rule in matched_rules:
            if rule["id"] in rule_recs:
                recommendations.append(rule_recs[rule["id"]])
        
        # Metadata-based recommendations
        if metadata.get("repeat_offender"):
            recommendations.append("🚫 Consider permanent IP blocklisting")
        
        return list(dict.fromkeys(recommendations))  # Remove duplicates while preserving order
    
    def get_stats(self) -> Dict[str, Any]:
        """Return detection statistics."""
        return {
            **self._stats,
            "threat_detection_rate": (
                self._stats["threats_detected"] / max(self._stats["total_analyzed"], 1)
            ) * 100
        }

# --------------------------
# Detection Service Worker
# --------------------------
class DetectionServiceWorker:
    """Async worker for processing threat detection jobs."""
    
    def __init__(self):
        self.redis_pool: Optional[ConnectionPool] = None
        self.redis_client: Optional[redis.Redis] = None
        self.db_pool: Optional[asyncpg.Pool] = None
        self.engine = ThreatDetectionEngine()
        self.running = False
        self._health_check_task = None
    
    async def start(self):
        """Initialize connections and start processing."""
        logger.info("🚀 Detection Service starting up...")
        
        # Initialize Redis with connection pool
        self.redis_pool = ConnectionPool.from_url(
            REDIS_URL,
            max_connections=REDIS_MAX_CONNECTIONS,
            decode_responses=True
        )
        self.redis_client = redis.Redis(connection_pool=self.redis_pool)
        
        try:
            await self.redis_client.ping()
            logger.info("✅ Redis connected")
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            raise
        
        # Initialize PostgreSQL connection pool
        try:
            self.db_pool = await asyncpg.create_pool(
                DATABASE_URL,
                min_size=DB_POOL_MIN,
                max_size=DB_POOL_MAX,
                command_timeout=60,
                server_settings={'application_name': 'detection_service'}
            )
            logger.info("✅ Database connected")
            await self._initialize_db_schema()
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            self.db_pool = None
        
        # Start health check task
        self._health_check_task = asyncio.create_task(self._periodic_health_check())
        
        self.running = True
        await self.process_queue()
    
    async def _initialize_db_schema(self):
        """Ensure database schema exists."""
        if not self.db_pool:
            return
        
        schema = """
        CREATE TABLE IF NOT EXISTS threat_detections (
            id VARCHAR(255) PRIMARY KEY,
            source_ip INET NOT NULL,
            threat_type VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            risk_score DECIMAL(5,2) NOT NULL,
            confidence DECIMAL(4,3) NOT NULL,
            matched_rules TEXT[],
            rule_categories TEXT[],
            recommendations TEXT[],
            processing_time_ms DECIMAL(10,2),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
        
        CREATE INDEX IF NOT EXISTS idx_threat_detections_ip ON threat_detections(source_ip);
        CREATE INDEX IF NOT EXISTS idx_threat_detections_severity ON threat_detections(severity);
        CREATE INDEX IF NOT EXISTS idx_threat_detections_created ON threat_detections(created_at DESC);
        """
        
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(schema)
            logger.info("✅ Database schema initialized")
        except Exception as e:
            logger.error(f"Failed to initialize schema: {e}")
    
    async def process_queue(self):
        """Main queue processing loop with batch support."""
        logger.info("👂 Listening for detection jobs...")
        
        while self.running:
            try:
                # Non-blocking pop with timeout
                job_key = await self.redis_client.blpop("detection_queue", timeout=QUEUE_TIMEOUT)
                
                if job_key:
                    job_data = json.loads(job_key[1])
                    await self.process_detection_job(job_data)
                
            except asyncio.CancelledError:
                logger.info("Queue processing cancelled")
                break
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in queue: {e}")
            except Exception as e:
                logger.error(f"Queue processing error: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    async def process_detection_job(self, job: Dict[str, Any]):
        """Process a single detection job."""
        threat_id = job.get("threat_id")
        log_data = job.get("log_data")
        source_ip = job.get("source_ip")
        metadata = job.get("metadata", {})
        
        if not all([threat_id, log_data, source_ip]):
            logger.error(f"Invalid job data: missing required fields")
            return
        
        logger.info(f"🔍 Processing detection job: {threat_id} from {source_ip}")
        
        try:
            # Check for repeat offenders
            repeat_count = await self._check_repeat_offender(source_ip)
            if repeat_count > 5:
                metadata["repeat_offender"] = True
            
            # Perform threat analysis
            result = await self.engine.analyze(log_data, source_ip, metadata)
            
            # Store results
            await asyncio.gather(
                self._store_in_db(threat_id, source_ip, result),
                self._cache_result(threat_id, source_ip, result),
                return_exceptions=True
            )
            
            # Publish alerts for high-risk threats
            if result["risk_score"] >= ALERT_THRESHOLD:
                await self.publish_alert(threat_id, source_ip, result)
            
            logger.info(f"✅ Detection completed: {threat_id} (Score: {result['risk_score']}, Type: {result['threat_type']})")
            
        except Exception as e:
            logger.error(f"Failed to process job {threat_id}: {e}", exc_info=True)
            # Store failed job for retry
            await self._enqueue_retry(job)
    
    async def _check_repeat_offender(self, source_ip: str) -> int:
        """Check if IP is a repeat offender."""
        try:
            # Count threats from this IP in last 24 hours
            pattern = f"threat:*:{source_ip}"
            keys = await self.redis_client.keys(pattern)
            return len(keys)
        except Exception as e:
            logger.warning(f"Failed to check repeat offender: {e}")
            return 0
    
    async def _store_in_db(self, threat_id: str, source_ip: str, result: Dict[str, Any]):
        """Store detection result in PostgreSQL."""
        if not self.db_pool:
            return
        
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO threat_detections 
                    (id, source_ip, threat_type, severity, risk_score, confidence, 
                     matched_rules, rule_categories, recommendations, processing_time_ms, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        updated_at = NOW()
                """,
                    threat_id, source_ip, result["threat_type"], result["severity"],
                    result["risk_score"], result["confidence"], result["matched_rules"],
                    result["rule_categories"], result["recommendations"], result["processing_time_ms"]
                )
        except Exception as e:
            logger.error(f"Failed to store result in DB: {e}")
    
    async def _cache_result(self, threat_id: str, source_ip: str, result: Dict[str, Any]):
        """Cache detection result in Redis."""
        try:
            cache_data = {"threat_id": threat_id, "source_ip": source_ip, **result}
            cache_key = f"threat:{threat_id}:{source_ip}"
            await self.redis_client.setex(cache_key, 86400, json.dumps(cache_data))
        except Exception as e:
            logger.error(f"Failed to cache result: {e}")
    
    async def publish_alert(self, threat_id: str, source_ip: str, result: Dict[str, Any]):
        """Publish high-severity alert to Redis pub/sub."""
        alert = {
            "alert_id": threat_id,
            "source_ip": source_ip,
            "severity": result["severity"],
            "risk_score": result["risk_score"],
            "threat_type": result["threat_type"],
            "matched_rules": result["matched_rules"],
            "recommendations": result["recommendations"][:3],  # Top 3
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            await self.redis_client.publish("security_alerts", json.dumps(alert))
            logger.warning(f"🚨 HIGH SEVERITY ALERT: {threat_id} - {source_ip} - Score: {result['risk_score']}")
        except Exception as e:
            logger.error(f"Failed to publish alert: {e}")
    
    async def _enqueue_retry(self, job: Dict[str, Any]):
        """Enqueue failed job for retry."""
        try:
            retry_count = job.get("retry_count", 0)
            if retry_count < 3:
                job["retry_count"] = retry_count + 1
                await self.redis_client.rpush("detection_queue_retry", json.dumps(job))
                logger.info(f"Enqueued job for retry (attempt {retry_count + 1})")
        except Exception as e:
            logger.error(f"Failed to enqueue retry: {e}")
    
    async def _periodic_health_check(self):
        """Periodic health check and metrics reporting."""
        while self.running:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                # Check Redis connection
                await self.redis_client.ping()
                
                # Check DB connection
                if self.db_pool:
                    async with self.db_pool.acquire() as conn:
                        await conn.fetchval("SELECT 1")
                
                # Log statistics
                stats = self.engine.get_stats()
                logger.info(f"📊 Health check: {stats}")
                
            except Exception as e:
                logger.error(f"Health check failed: {e}")
    
    async def shutdown(self):
        #Graceful shutdown
        logger.info("🛑 Detection Service shutting down...")
        self.running = False
        
        # Cancel health check
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        # Close connections
        if self.redis_client:
            await self.redis_client.close()
        if self.redis_pool:
            await self.redis_pool.disconnect()
        if self.db_pool:
            await self.db_pool.close()
        
        logger.info("✅ Shutdown complete")


async def main():
    """Main application entry point."""
    worker = DetectionServiceWorker()
    
    try:
        await worker.start()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal (Ctrl+C)")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        await worker.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
