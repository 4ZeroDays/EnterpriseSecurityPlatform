
import asyncio
import json
import logging
import os
import re
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import joblib
import numpy as np
import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import Response
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel, Field, field_validator
from redis.asyncio.connection import ConnectionPool
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://threat_user:supersecret@localhost:5432/security_platform")
REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "50"))
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "5"))
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "20"))
QUEUE_TIMEOUT = int(os.getenv("QUEUE_TIMEOUT", "5"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
BATCH_WAIT_MS = int(os.getenv("BATCH_WAIT_MS", "100"))
MAX_LOG_SIZE = int(os.getenv("MAX_LOG_SIZE", "100000"))
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "70.0"))
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))
ML_WEIGHT_ISOLATION = float(os.getenv("ML_WEIGHT_ISOLATION", "0.5"))
ML_WEIGHT_RANDOM_FOREST = float(os.getenv("ML_WEIGHT_RANDOM_FOREST", "0.5"))
IPSET_TIMEOUT = int(os.getenv("IPSET_TIMEOUT", "2"))
BLOCKED_IP_CACHE_TTL = int(os.getenv("BLOCKED_IP_CACHE_TTL", "300"))
MAX_RETRY_BACKOFF = int(os.getenv("MAX_RETRY_BACKOFF", "300"))

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "service": "detection-engine", "message": "%(message)s"}'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
redis_up = Gauge("redis_up", "Status of the Redis connection (1=up, 0=down)")
db_up = Gauge("db_up", "Status of the database connection (1=up, 0=down)")
redis_response_time = Histogram("redis_response_time_seconds", "Response time for Redis check")
db_response_time = Histogram("db_response_time_seconds", "Response time for DB check")
log_analyzed_total = Counter("log_analyzed_total", "Total number of logs analyzed")
matched_rules_count = Gauge("matched_rules_count", "Number of rules matched in last analysis")
ml_score_gauge = Gauge("ml_score", "ML risk score from last analysis")
risk_score_gauge = Gauge("risk_score", "Overall risk score from last analysis")
threat_detected_gauge = Gauge("threat_detected", "Whether a threat was detected (1=yes, 0=no)")
deadletter_count = Counter("deadletter_count", "Number of jobs moved to dead-letter queue")
alert_published_total = Counter("alert_published_total", "Total alerts published")
alert_rate_limited_total = Counter("alert_rate_limited_total", "Total alerts rate-limited")
batch_processed_total = Counter("batch_processed_total", "Total batches processed")
ipset_cache_hits = Counter("ipset_cache_hits", "IP blocklist cache hits")
ipset_cache_misses = Counter("ipset_cache_misses", "IP blocklist cache misses")
detection_duration = Histogram("detection_duration_seconds", "Time spent on threat detection")
queue_size_gauge = Gauge("queue_size", "Current detection queue size")

# Global worker instance
worker_instance: Optional['DetectionServiceWorker'] = None


# Pydantic models
class DetectionJobPayload(BaseModel):
    """Validated detection job payload."""
    threat_id: str = Field(..., min_length=1, max_length=255)
    log_data: str = Field(..., min_length=1)
    source_ip: str = Field(..., pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    retry_count: int = Field(default=0, ge=0)
    
    @field_validator('log_data')
    def truncate_log_data(cls, v):
        if len(v) > MAX_LOG_SIZE:
            logger.warning(f"Log data truncated from {len(v)} to {MAX_LOG_SIZE} bytes")
            return v[:MAX_LOG_SIZE]
        return v


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    redis_connected: bool
    db_connected: bool
    worker_running: bool
    stats: Dict[str, Any]


def load_ml_models():
    """Load ML models from disk."""
    try:
        model_path = os.getenv("MODEL_PATH", "models")
        isolation_model, random_forest_model, vectorizer = None, None, None
        
        try:
            isolation_model = joblib.load(f"{model_path}/anomaly_model.pkl")
            logger.info("Isolation Forest model loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load Isolation Forest model: {e}")
        
        try:
            random_forest_model = joblib.load(f"{model_path}/random_forest_model.pkl")
            logger.info("Random Forest model loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load Random Forest model: {e}")
        
        try:
            vectorizer = joblib.load(f"{model_path}/tfidf_vectorizer.pkl")
            logger.info("TF-IDF Vectorizer loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load TF-IDF Vectorizer: {e}")
        
        if isolation_model is None and random_forest_model is None:
            logger.warning("No ML models loaded - ML detection disabled")
        else:
            logger.info("✅ ML models loaded successfully")
        
        return isolation_model, random_forest_model, vectorizer
    except Exception as e:
        logger.error(f"Error loading ML models: {e}")
        return None, None, None


isolation_model, random_forest_model, vectorizer = load_ml_models()


class ThreatDetectionEngine:
    """Core detection engine with rule-based and ML-based analysis."""
    
    def __init__(self):
        self.rules = self._load_detection_rules()
        self.ml_enabled: bool = (isolation_model is not None or random_forest_model is not None) and vectorizer is not None
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
        """Analyze log data for threats."""
        start_time = time.time()
        self._stats["total_analyzed"] += 1
        log_analyzed_total.inc()
        
        matched_rules = []
        total_score = 0.0
        log_lower = log_data.lower()
        
        # Rule-based detection
        for rule in self.rules:
            try:
                if re.search(rule["pattern"], log_lower, re.IGNORECASE):
                    matched_rules.append(rule)
                    total_score += rule.get("score_weight", 0.0)
                    logger.debug(f"Rule matched: {rule['id']} for IP {source_ip}")
            except re.error as e:
                logger.error(f"Regex error in rule {rule['id']}: {e}")
        
        matched_rules_count.set(len(matched_rules))
        
        # ml based detection
        ml_risk_score = 0.0
        if self.ml_enabled:
            try:
                ml_risk_score = await self._ml_anomaly_detection(log_data, source_ip)
                total_score += ml_risk_score
            except Exception as e:
                self._stats["ml_errors"] += 1
                logger.warning(f"ML analysis failed for IP {source_ip}: {e}")
        
        ml_score_gauge.set(ml_risk_score)
        
        # Calculate final risk score
        risk_score = max(min(total_score, 100.0), 0.0)
        risk_score_gauge.set(risk_score)
        
        
        threat_type, severity, confidence = self._classify_threat(matched_rules, risk_score)
        threat_detected = 1 if threat_type != "BENIGN" else 0
        threat_detected_gauge.set(threat_detected)
        
        if threat_detected:
            self._stats["threats_detected"] += 1
        

        recommendations = self._generate_recommendations(risk_score, matched_rules, metadata)
        
        processing_time = time.time() - start_time
        detection_duration.observe(processing_time)
        
        return {
            "risk_score": round(risk_score, 2),
            "threat_type": threat_type,
            "severity": severity,
            "confidence": round(confidence, 3),
            "matched_rules": [r["id"] for r in matched_rules],
            "rule_categories": list(set(r.get("category") for r in matched_rules if "category" in r)),
            "recommendations": recommendations,
            "processing_time_ms": round(processing_time * 1000, 2),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "ml_enabled": self.ml_enabled,
            "ml_score": round(ml_risk_score, 2),
            "matched_rules_count": len(matched_rules),
            "threat_detected": threat_detected,
            "source_ip": source_ip,
            "metadata": metadata,
        }
    
    async def _ml_anomaly_detection(self, log_data: str, source_ip: str) -> float:
        #Perform ML-based anomaly detection with configurable weights
        try:
            loop = asyncio.get_event_loop()
            
            
            try:
                x = await loop.run_in_executor(None, vectorizer.transform, [log_data])
            except Exception as e:
                logger.warning(f"Vectorizer transform error: {e}")
                return 0.0
            
            
            iso_risk = 0.0
            if isolation_model is not None:
                try:
                    iso_score = await loop.run_in_executor(None, isolation_model.decision_function, x)
                    iso_risk = max(0.0, min((1 - iso_score[0]) * 100.0, 100.0))
                except Exception as e:
                    logger.warning(f"IsolationForest score error: {e}")
            
            
            rf_risk = 0.0
            if random_forest_model is not None:
                try:
                    rf_pred = await loop.run_in_executor(None, random_forest_model.predict, x)
                    rf_risk = 100.0 if rf_pred[0] == 1 else 0.0
                except Exception as e:
                    logger.warning(f"RandomForest prediction error: {e}")
            
            
            combined_risk = (iso_risk * ML_WEIGHT_ISOLATION) + (rf_risk * ML_WEIGHT_RANDOM_FOREST)
            logger.debug(f"ML scores - Isolation: {iso_risk:.2f}, RF: {rf_risk:.2f}, Combined: {combined_risk:.2f} for IP {source_ip}")
            return combined_risk
        except Exception as e:
            self._stats["ml_errors"] += 1
            logger.warning(f"ML analysis failed for IP {source_ip}: {e}")
            return 0.0
    
    def _classify_threat(self, matched_rules: List[Dict], risk_score: float) -> tuple:
        #Classify threat type, severity, and confidence.
        if not matched_rules:
            return "BENIGN", "LOW", 0.15
        
        highest_rule = max(matched_rules, key=lambda r: r["score_weight"])
        threat_type = highest_rule["id"]
        severity = highest_rule["severity"]
        
        base_confidence: float = 0.75
        rule_count_boost: float = min(0.05 * len(matched_rules), 0.15)
        score_boost: float = min((risk_score / 100) * 0.10, 0.10)
        confidence: float = min(base_confidence + rule_count_boost + score_boost, 0.99)
        
        return threat_type, severity, confidence
    
    def _generate_recommendations(self, risk_score: float, matched_rules: List[Dict], metadata: Dict[str, Any]) -> List[str]:
        #Generate contextual security recommendations.
        recommendations = []
        
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
        
        if metadata.get("repeat_offender"):
            recommendations.append("🚫 Consider permanent IP blocklisting")
        
        return list(dict.fromkeys(recommendations))
    
    def get_stats(self) -> Dict[str, Any]:
        
        return {
            **self._stats,
            "threat_detection_rate": (
                self._stats["threats_detected"] / max(self._stats["total_analyzed"], 1)
            ) * 100
        }


class DetectionServiceWorker:
    
    
    def __init__(self):
        self.redis_pool: Optional[ConnectionPool] = None
        self.redis_client: Optional[redis.Redis] = None
        self.db_pool: Optional[asyncpg.Pool] = None
        self.engine = ThreatDetectionEngine()
        self.running = False
        self._health_check_task = None
        self._worker_task = None
        self._blocked_ip_cache: Dict[str, bool] = {}
        self._blocked_ip_cache_times: Dict[str, float] = {}
        self._alert_cooldowns: Dict[str, float] = {}
        self._pending_jobs: List[DetectionJobPayload] = []
    
    async def start(self):
        """Initialize connections and start processing."""
        logger.info("🚀 Detection Service starting up...")
        
        self.redis_pool = ConnectionPool.from_url(
            REDIS_URL,
            max_connections=REDIS_MAX_CONNECTIONS,
            decode_responses=True
        )
        self.redis_client = redis.Redis(connection_pool=self.redis_pool)
        
        try:
            await self.redis_client.ping()
            redis_up.set(1)
            logger.info("✅ Redis connected")
        except Exception as e:
            redis_up.set(0)
            logger.error(f"❌ Redis connection failed: {e}")
            raise
        
        try:
            self.db_pool = await asyncpg.create_pool(
                DATABASE_URL,
                min_size=DB_POOL_MIN,
                max_size=DB_POOL_MAX,
                command_timeout=60,
                server_settings={'application_name': 'detection_service'}
            )
            db_up.set(1)
            logger.info("✅ Database connected")
            await self._initialize_db_schema()
        except Exception as e:
            db_up.set(0)
            logger.error(f"❌ Database connection failed: {e}")
            self.db_pool = None
        
        self._health_check_task = asyncio.create_task(self._periodic_health_check())
        
        self.running = True
        self._worker_task = asyncio.create_task(self.process_queue())
    
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
            ml_enabled BOOLEAN DEFAULT FALSE,
            ml_score DECIMAL(5,2),
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
        
        CREATE INDEX IF NOT EXISTS idx_threat_detections_ip ON threat_detections(source_ip);
        CREATE INDEX IF NOT EXISTS idx_threat_detections_severity ON threat_detections(severity);
        CREATE INDEX IF NOT EXISTS idx_threat_detections_created ON threat_detections(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_threat_detections_risk_score ON threat_detections(risk_score DESC);
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
        batch_start_time = time.time()
        
        while self.running:
            try:
                job_key = await self.redis_client.blpop("detection_queue", timeout=QUEUE_TIMEOUT)
                
                if job_key:
                    try:
                        job_data = json.loads(job_key[1])
                        job = DetectionJobPayload(**job_data)
                        self._pending_jobs.append(job)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in queue: {e}")
                    except Exception as e:
                        logger.error(f"Invalid job payload: {e}")
                
              
                try:
                    q_size = await self.redis_client.llen("detection_queue")
                    queue_size_gauge.set(q_size)
                except Exception:
                    pass
                
          
                current_time = time.time()
                batch_timeout_reached = (current_time - batch_start_time) * 1000 >= BATCH_WAIT_MS
                
                if len(self._pending_jobs) >= BATCH_SIZE or (self._pending_jobs and batch_timeout_reached):
                    await self._process_batch(self._pending_jobs)
                    self._pending_jobs.clear()
                    batch_start_time = current_time
                    batch_processed_total.inc()
                
                # Small sleep after timeout to reduce cpu churn
                if not job_key:
                    await asyncio.sleep(0.1)
                
            except asyncio.CancelledError:
                logger.info("Queue processing cancelled")
                break
            except Exception as e:
                logger.error(f"Queue processing error: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    async def _process_batch(self, jobs: List[DetectionJobPayload]):
        #Process a batch of jobs concurrently.
        if not jobs:
            return
        
        logger.info(f"🔄 Processing batch of {len(jobs)} jobs")
        tasks = [self.process_detection_job(job) for job in jobs]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def process_detection_job(self, job: DetectionJobPayload):
        #Process a single detection job.
        logger.info(f"🔍 Processing detection job: {job.threat_id} from {job.source_ip}")
        
        try:
            #
            is_blocked = await self._check_blocked_ip(job.source_ip)
            if is_blocked:
                job.metadata["repeat_offender"] = True
            
            # Perform threat analysis
            result = await self.engine.analyze(job.log_data, job.source_ip, job.metadata)
            
            
            await asyncio.gather(
                self._store_in_db(job.threat_id, job.source_ip, result),
                self._cache_result(job.threat_id, job.source_ip, result),
                return_exceptions=True
            )
            
            # Publish alert with rate limiting
            if result["risk_score"] >= ALERT_THRESHOLD:
                await self._publish_alert_with_ratelimit(job.threat_id, job.source_ip, result)
            
            logger.info(f"✅ Detection completed: {job.threat_id} (Score: {result['risk_score']}, Type: {result['threat_type']})")
            
        except Exception as e:
            logger.error(f"Failed to process job {job.threat_id}: {e}", exc_info=True)
            await self._enqueue_retry(job)
    
    async def _check_blocked_ip(self, source_ip: str) -> bool:

        current_time = time.time()
        if source_ip in self._blocked_ip_cache:
            cache_time = self._blocked_ip_cache_times.get(source_ip, 0)
            if current_time - cache_time < BLOCKED_IP_CACHE_TTL:
                ipset_cache_hits.inc()
                return self._blocked_ip_cache[source_ip]
        
        ipset_cache_misses.inc()
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "ipset", "test", "blocked_ips", source_ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=IPSET_TIMEOUT)
                is_blocked = proc.returncode == 0
            except asyncio.TimeoutError:
                logger.warning(f"ipset check timed out for {source_ip}")
                proc.kill()
                await proc.wait()
                is_blocked = False
            
            # Cache result
            self._blocked_ip_cache[source_ip] = is_blocked
            self._blocked_ip_cache_times[source_ip] = current_time
            
            # Evict old cache entries
            if len(self._blocked_ip_cache) > 10000:
                self._evict_old_cache_entries()
            
            return is_blocked
        except FileNotFoundError:
            logger.warning("ipset command not found - skipping blocked IP check")
            return False
        except Exception as e:
            logger.warning(f"Failed to check ipset for {source_ip}: {e}")
            return False
    
    def _evict_old_cache_entries(self):
        #evict oldest 20% of cache entries
        current_time = time.time()
        sorted_entries = sorted(
            self._blocked_ip_cache_times.items(),
            key=lambda x: x[1]
        )
        evict_count = len(sorted_entries) // 5
        for ip, _ in sorted_entries[:evict_count]:
            self._blocked_ip_cache.pop(ip, None)
            self._blocked_ip_cache_times.pop(ip, None)
        logger.info(f"Evicted {evict_count} old cache entries")
    
    async def _store_in_db(self, threat_id: str, source_ip: str, result: Dict[str, Any]):
        #store detection result in PostgreSQL with full field updates
        if not self.db_pool:
            return
        
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO threat_detections 
                    (id, source_ip, threat_type, severity, risk_score, confidence, 
                     matched_rules, rule_categories, recommendations, processing_time_ms,
                     ml_enabled, ml_score, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        threat_type = EXCLUDED.threat_type,
                        severity = EXCLUDED.severity,
                        risk_score = EXCLUDED.risk_score,
                        confidence = EXCLUDED.confidence,
                        matched_rules = EXCLUDED.matched_rules,
                        rule_categories = EXCLUDED.rule_categories,
                        recommendations = EXCLUDED.recommendations,
                        processing_time_ms = EXCLUDED.processing_time_ms,
                        ml_enabled = EXCLUDED.ml_enabled,
                        ml_score = EXCLUDED.ml_score,
                        updated_at = NOW()
                """,
                    threat_id, source_ip, result["threat_type"], result["severity"],
                    result["risk_score"], result["confidence"], result["matched_rules"],
                    result["rule_categories"], result["recommendations"], result["processing_time_ms"],
                    result["ml_enabled"], result["ml_score"]
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
    
    async def _publish_alert_with_ratelimit(self, threat_id: str, source_ip: str, result: Dict[str, Any]):
        #Publish alert with per-IP rate limiting and deduplication.
        current_time = time.time()
        
        # Check cooldown
        last_alert_time = self._alert_cooldowns.get(source_ip, 0)
        if current_time - last_alert_time < ALERT_COOLDOWN_SECONDS:
            alert_rate_limited_total.inc()
            logger.debug(f"Alert rate-limited for {source_ip} (cooldown: {ALERT_COOLDOWN_SECONDS}s)")
            return
        
        # Update cooldown
        self._alert_cooldowns[source_ip] = current_time
        
        # Clean up old cooldowns keep last 1000
        if len(self._alert_cooldowns) > 1000:
            sorted_cooldowns = sorted(self._alert_cooldowns.items(), key=lambda x: x[1])
            self._alert_cooldowns = dict(sorted_cooldowns[-1000:])
        
        alert = {
            "alert_id": threat_id,
            "source_ip": source_ip,
            "severity": result["severity"],
            "risk_score": result["risk_score"],
            "threat_type": result["threat_type"],
            "matched_rules": result["matched_rules"],
            "recommendations": result["recommendations"][:3],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            await self.redis_client.publish("security_alerts", json.dumps(alert))
            alert_published_total.inc()
            
            if result['severity'] == 'HIGH':
                logger.warning(f"🚨 HIGH SEVERITY ALERT: {threat_id} - {source_ip} - Score: {result['risk_score']}")
            elif result['severity'] == 'CRITICAL':
                logger.critical(f"🚨 CRITICAL SEVERITY ALERT: {threat_id} - {source_ip} - Score: {result['risk_score']}")
                
                # Optional: Send external alerts (email, Slack, PagerDuty)
                await self._send_external_alert(alert)
        except Exception as e:
            logger.error(f"Failed to publish alert: {e}")
    
    async def _send_external_alert(self, alert: Dict[str, Any]):
      #already added but in different file can add here for sending additional info 
        pass #placeholder
    
    async def _enqueue_retry(self, job: DetectionJobPayload):
        #enqueue failed job for retry with capped exponential backoff.
        try:
            max_retries = 10
            base_backoff = 2
            
            if job.retry_count < max_retries:
                # Cap backoff at MAX_RETRY_BACKOFF
                backoff = min(base_backoff ** job.retry_count, MAX_RETRY_BACKOFF)
                logger.info(f"Retrying job {job.threat_id} attempt {job.retry_count + 1} after {backoff}s")
                await asyncio.sleep(backoff)
                
                job.retry_count += 1
                try:
                    await self.redis_client.rpush("detection_queue_retry", job.json())
                    logger.info(f"Enqueued job {job.threat_id} for retry (attempt {job.retry_count})")
                except redis.exceptions.RedisError as redis_err:
                    logger.error(f"Redis error while enqueuing retry: {redis_err}")
            else:
                # Move to dead-letter queue
                try:
                    await self.redis_client.rpush("detection_queue_deadletter", job.json())
                    deadletter_count.inc()
                    logger.warning(
                        f"Job {job.threat_id} from {job.source_ip} exceeded max retries ({max_retries}) "
                        "and was moved to dead-letter queue"
                    )
                except redis.exceptions.RedisError as redis_err:
                    logger.error(f"Failed to move job {job.threat_id} to dead-letter queue: {redis_err}")
        except Exception as e:
            logger.error(f"Failed to enqueue retry for job {job.threat_id}: {e}")
    
    async def _periodic_health_check(self):
        """Periodic health check with escalation for persistent failures."""
        redis_failure_count: int = 0
        db_failure_count: int = 0
        last_escalation: float = 0
        escalation_cooldown: int = 3600  
        
        while self.running:
            try:
                await asyncio.sleep(60)
                current_time = time.time()
                
                # Redis health check
                start_time = time.perf_counter()
                try:
                    await self.redis_client.ping()
                    end_time = time.perf_counter()
                    redis_failure_count = 0
                    redis_up.set(1)
                    redis_response_time.observe(end_time - start_time)
                except Exception as e:
                    end_time = time.perf_counter()
                    redis_failure_count += 1
                    redis_up.set(0)
                    redis_response_time.observe(end_time - start_time)
                    logger.error(f"Redis health check failed (count: {redis_failure_count}): {e}")
                
                # Database health check
                start_time = time.perf_counter()
                try:
                    if self.db_pool:
                        async with self.db_pool.acquire() as conn:
                            await conn.fetchval("SELECT 1")
                    end_time = time.perf_counter()
                    db_failure_count = 0
                    db_up.set(1)
                    db_response_time.observe(end_time - start_time)
                except Exception as e:
                    end_time = time.perf_counter()
                    db_failure_count += 1
                    db_up.set(0)
                    db_response_time.observe(end_time - start_time)
                    logger.error(f"Database health check failed (count: {db_failure_count}): {e}")
                
                # Escalate persistent failures
                if (redis_failure_count >= 5 or db_failure_count >= 5) and \
                   (current_time - last_escalation) > escalation_cooldown:
                    await self._escalate_health_failure(redis_failure_count, db_failure_count)
                    last_escalation = current_time
                
               
                stats = self.engine.get_stats()
                logger.info(
                    f"📊 Health check - "
                    f"Analyzed: {stats['total_analyzed']}, "
                    f"Threats: {stats['threats_detected']}, "
                    f"ML errors: {stats['ml_errors']}, "
                    f"Detection rate: {stats['threat_detection_rate']:.2f}%"
                )
            except asyncio.CancelledError:
                logger.info("Health check task cancelled")
                break
            except Exception as e:
                logger.critical(f"Unexpected error in health check loop: {e}", exc_info=True)
                await asyncio.sleep(300)
    
    async def _escalate_health_failure(self, redis_failures: int, db_failures: int):
        #escalate persistent health failures to external monitoring.
        message = (
            f"🚨 CRITICAL SYSTEM HEALTH ALERT\n"
            f"Redis failures: {redis_failures}\n"
            f"Database failures: {db_failures}\n"
            f"Service: Detection Engine\n"
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n"
            f"Action required: Immediate investigation"
        )
        
        logger.critical(message)
        

        try:
            alert_key = f"critical_alert:{int(time.time())}"
            await self.redis_client.setex(alert_key, 86400, message)
        except Exception as e:
            logger.error(f"Failed to store critical alert: {e}")
    
    async def shutdown(self):
        #graceful shutdown with pending job handling.
        logger.info("🛑 Detection Service shutting down...")
        self.running = False
        
        # process remaining pending jobs
        if self._pending_jobs:
            logger.info(f"Processing {len(self._pending_jobs)} pending jobs before shutdown")
            await self._process_batch(self._pending_jobs)
        
        
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        
        
        if self.redis_client:
            await self.redis_client.close()
        if self.redis_pool:
            await self.redis_pool.disconnect()
        if self.db_pool:
            await self.db_pool.close()
        
        logger.info("✅ Shutdown complete")


# FastAPI application
@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager."""
    global worker_instance
    worker_instance = DetectionServiceWorker()
    await worker_instance.start()
    try:
        yield
    finally:
        await worker_instance.shutdown()


app = FastAPI(title="Detection Service", version="2.0.0", lifespan=lifespan)


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    global worker_instance
    
    redis_connected = False
    db_connected = False
    worker_running = False
    stats = {}
    
    if worker_instance:
        worker_running = worker_instance.running
        stats = worker_instance.engine.get_stats()
        
        # Check Redis
        try:
            if worker_instance.redis_client:
                await worker_instance.redis_client.ping()
                redis_connected = True
        except Exception:
            pass
        
        # Check DB
        try:
            if worker_instance.db_pool:
                async with worker_instance.db_pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                db_connected = True
        except Exception:
            pass
    
    status = "healthy" if (redis_connected and worker_running) else "degraded"
    
    return HealthResponse(
        status=status,
        redis_connected=redis_connected,
        db_connected=db_connected,
        worker_running=worker_running,
        stats=stats
    )


@app.post("/analyze")
async def analyze_threat(job: DetectionJobPayload):
    """Manual threat analysis endpoint."""
    global worker_instance
    
    if not worker_instance or not worker_instance.running:
        raise HTTPException(status_code=503, detail="Worker not running")
    
    try:
        result = await worker_instance.engine.analyze(
            job.log_data,
            job.source_ip,
            job.metadata
        )
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """Get detection engine statistics."""
    global worker_instance
    
    if not worker_instance:
        raise HTTPException(status_code=503, detail="Worker not initialized")
    
    return worker_instance.engine.get_stats()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
