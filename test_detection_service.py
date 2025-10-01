# Test Suite for Detection Service
# Run with: pytest test_detection_service.py -v
import pytest
import asyncio
import json
import uuid
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import asyncpg
import redis.asyncio as redis

# Import the service (adjust import path as needed)
from detection_service import (
    ThreatDetectionEngine,
    DetectionServiceWorker,
    load_ml_models
)

# --------------------------
# Unit Tests - Detection Engine
# --------------------------
class TestThreatDetectionEngine:
    """Test the core detection logic."""
    
    @pytest.fixture
    def engine(self):
        """Create a detection engine instance."""
        return ThreatDetectionEngine()
    
    def test_engine_initialization(self, engine):
        """Test that engine initializes correctly."""
        assert engine is not None
        assert len(engine.rules) > 0
        assert isinstance(engine._stats, dict)
    
    @pytest.mark.asyncio
    async def test_sql_injection_detection(self, engine):
        """Test SQL injection pattern detection."""
        log_data = "SELECT * FROM users WHERE username='admin' OR 1=1--"
        result = await engine.analyze(log_data, "192.168.1.100", {})
        
        assert result["risk_score"] > 70
        assert "SQL_INJECTION" in result["matched_rules"]
        assert result["severity"] == "CRITICAL"
        assert result["threat_type"] == "SQL_INJECTION"
    
    @pytest.mark.asyncio
    async def test_xss_detection(self, engine):
        """Test XSS pattern detection."""
        log_data = "<script>alert('XSS')</script>"
        result = await engine.analyze(log_data, "10.0.0.5", {})
        
        assert result["risk_score"] > 60
        assert "XSS_ATTACK" in result["matched_rules"]
        assert result["severity"] == "HIGH"
    
    @pytest.mark.asyncio
    async def test_path_traversal_detection(self, engine):
        """Test path traversal detection."""
        log_data = "GET ../../etc/passwd HTTP/1.1"
        result = await engine.analyze(log_data, "172.16.0.1", {})
        
        assert result["risk_score"] > 60
        assert "PATH_TRAVERSAL" in result["matched_rules"]
    
    @pytest.mark.asyncio
    async def test_command_injection_detection(self, engine):
        """Test command injection detection."""
        log_data = "filename=test.txt; cat /etc/passwd"
        result = await engine.analyze(log_data, "192.168.1.50", {})
        
        assert result["risk_score"] > 70
        assert "COMMAND_INJECTION" in result["matched_rules"]
    
    @pytest.mark.asyncio
    async def test_benign_traffic(self, engine):
        """Test that benign traffic is not flagged."""
        log_data = "GET /api/users/profile HTTP/1.1 User-Agent: Mozilla/5.0"
        result = await engine.analyze(log_data, "10.0.0.1", {})
        
        assert result["risk_score"] < 40
        assert result["threat_type"] == "BENIGN"
        assert result["severity"] == "LOW"
    
    @pytest.mark.asyncio
    async def test_multiple_rules_match(self, engine):
        """Test that multiple matching rules increase score."""
        log_data = "<script>alert('XSS')</script> OR 1=1-- ../../etc/passwd"
        result = await engine.analyze(log_data, "192.168.1.1", {})
        
        assert len(result["matched_rules"]) >= 2
        assert result["risk_score"] > 80
    
    @pytest.mark.asyncio
    async def test_recommendations_generated(self, engine):
        """Test that recommendations are generated."""
        log_data = "SELECT * FROM users WHERE id='1' OR '1'='1'"
        result = await engine.analyze(log_data, "192.168.1.1", {})
        
        assert len(result["recommendations"]) > 0
        assert any("SQL" in rec or "parameterized" in rec for rec in result["recommendations"])
    
    @pytest.mark.asyncio
    async def test_repeat_offender_recommendation(self, engine):
        """Test repeat offender generates specific recommendation."""
        log_data = "malicious payload"
        metadata = {"repeat_offender": True}
        result = await engine.analyze(log_data, "192.168.1.1", metadata)
        
        assert any("blocklisting" in rec.lower() for rec in result["recommendations"])
    
    def test_get_stats(self, engine):
        """Test statistics tracking."""
        stats = engine.get_stats()
        assert "total_analyzed" in stats
        assert "threats_detected" in stats
        assert "threat_detection_rate" in stats

# --------------------------
# Integration Tests - Worker
# --------------------------
class TestDetectionServiceWorker:
    """Test the service worker with mocked dependencies."""
    
    @pytest.fixture
    async def worker(self):
        """Create a worker instance."""
        worker = DetectionServiceWorker()
        yield worker
        # Cleanup
        if worker.running:
            await worker.shutdown()
    
    @pytest.mark.asyncio
    async def test_process_detection_job(self, worker):
        """Test processing a single detection job."""
        # Mock dependencies
        worker.redis_client = AsyncMock()
        worker.db_pool = AsyncMock()
        
        job = {
            "threat_id": str(uuid.uuid4()),
            "log_data": "SELECT * FROM users WHERE id=1 OR 1=1",
            "source_ip": "192.168.1.100",
            "metadata": {}
        }
        
        await worker.process_detection_job(job)
        
        # Verify Redis cache was called
        assert worker.redis_client.setex.called
    
    @pytest.mark.asyncio
    async def test_invalid_job_handling(self, worker):
        """Test handling of invalid job data."""
        worker.redis_client = AsyncMock()
        
        # Missing required fields
        invalid_job = {"threat_id": "123"}
        
        # Should not raise exception
        await worker.process_detection_job(invalid_job)
    
    @pytest.mark.asyncio
    async def test_alert_publishing(self, worker):
        """Test high-risk alert publishing."""
        worker.redis_client = AsyncMock()
        
        threat_id = str(uuid.uuid4())
        source_ip = "10.0.0.1"
        result = {
            "risk_score": 95.0,
            "severity": "CRITICAL",
            "threat_type": "SQL_INJECTION",
            "matched_rules": ["SQL_INJECTION"],
            "recommendations": ["Block IP", "Review logs"]
        }
        
        await worker.publish_alert(threat_id, source_ip, result)
        
        # Verify publish was called
        assert worker.redis_client.publish.called
        call_args = worker.redis_client.publish.call_args
        assert call_args[0][0] == "security_alerts"

# --------------------------
# Manual Testing Script
# --------------------------
async def manual_test_full_flow():
    """
    Manual test to verify end-to-end flow.
    Requires Redis and PostgreSQL running.
    """
    print("🧪 Starting Manual End-to-End Test")
    print("=" * 60)
    
    # Initialize Redis
    try:
        redis_client = await redis.from_url("redis://localhost:6379", decode_responses=True)
        await redis_client.ping()
        print("✅ Redis connection successful")
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        print("   Start Redis with: docker run -d -p 6379:6379 redis")
        return
    
    # Test cases
    test_cases = [
        {
            "name": "SQL Injection Attack",
            "log_data": "GET /api/users?id=1' OR '1'='1'-- HTTP/1.1",
            "source_ip": "192.168.1.100",
            "expected_threat": True
        },
        {
            "name": "XSS Attack",
            "log_data": "POST /comment body=<script>alert('XSS')</script>",
            "source_ip": "10.0.0.5",
            "expected_threat": True
        },
        {
            "name": "Path Traversal",
            "log_data": "GET /files?path=../../../../etc/passwd",
            "source_ip": "172.16.0.1",
            "expected_threat": True
        },
        {
            "name": "Normal Traffic",
            "log_data": "GET /api/users/profile HTTP/1.1 User-Agent: Chrome",
            "source_ip": "10.0.0.1",
            "expected_threat": False
        },
        {
            "name": "Malware Signature",
            "log_data": "<?php eval(base64_decode($_POST['cmd'])); ?>",
            "source_ip": "192.168.1.200",
            "expected_threat": True
        }
    ]
    
    # Queue jobs
    print("\n📤 Queueing detection jobs...")
    for i, test in enumerate(test_cases, 1):
        job = {
            "threat_id": f"test-{uuid.uuid4()}",
            "log_data": test["log_data"],
            "source_ip": test["source_ip"],
            "metadata": {"test_case": test["name"]}
        }
        
        await redis_client.rpush("detection_queue", json.dumps(job))
        print(f"   {i}. Queued: {test['name']}")
    
    print(f"\n✅ Queued {len(test_cases)} test jobs")
    print("\n📝 Next steps:")
    print("   1. Start the detection service: python detection_service.py")
    print("   2. Monitor logs for processing results")
    print("   3. Check Redis for cached results: redis-cli KEYS 'threat:*'")
    print("   4. Query PostgreSQL for stored detections")
    
    # Clean up
    await redis_client.close()
    print("\n" + "=" * 60)

# --------------------------
# Quick Test - No Dependencies
# --------------------------
async def quick_test_detection_only():
    """Quick test of detection engine without external dependencies."""
    print("🧪 Quick Detection Engine Test (No Dependencies)")
    print("=" * 60)
    
    engine = ThreatDetectionEngine()
    
    test_payloads = [
        ("SQL Injection", "admin' OR 1=1--"),
        ("XSS", "<script>alert(1)</script>"),
        ("Path Traversal", "../../etc/passwd"),
        ("Command Injection", "; cat /etc/shadow"),
        ("Normal Request", "GET /api/health HTTP/1.1")
    ]
    
    print("\n🔍 Running Detection Tests:\n")
    
    for name, payload in test_payloads:
        result = await engine.analyze(payload, "192.168.1.100", {})
        
        status = "🚨 THREAT" if result["risk_score"] > 40 else "✅ CLEAN"
        print(f"{status} {name:20s} | Score: {result['risk_score']:5.1f} | Type: {result['threat_type']}")
        
        if result["matched_rules"]:
            print(f"         Rules: {', '.join(result['matched_rules'])}")
        if result["recommendations"]:
            print(f"         Action: {result['recommendations'][0]}")
        print()
    
    # Show statistics
    stats = engine.get_stats()
    print("\n📊 Detection Statistics:")
    print(f"   Total Analyzed: {stats['total_analyzed']}")
    print(f"   Threats Detected: {stats['threats_detected']}")
    print(f"   Detection Rate: {stats['threat_detection_rate']:.1f}%")
    print("\n" + "=" * 60)

# --------------------------
# Performance Test
# --------------------------
async def performance_test():
    """Test detection engine performance."""
    print("🧪 Performance Test")
    print("=" * 60)
    
    engine = ThreatDetectionEngine()
    iterations = 1000
    
    payloads = [
        "SELECT * FROM users WHERE id='1' OR '1'='1'",
        "<script>alert('test')</script>",
        "../../etc/passwd",
        "GET /api/users HTTP/1.1"
    ]
    
    print(f"\n⏱️  Processing {iterations} detections...\n")
    
    start = datetime.now()
    
    for i in range(iterations):
        payload = payloads[i % len(payloads)]
        await engine.analyze(payload, f"192.168.1.{i % 255}", {})
    
    duration = (datetime.now() - start).total_seconds()
    
    print(f"✅ Completed {iterations} detections in {duration:.2f}s")
    print(f"   Average: {(duration/iterations)*1000:.2f}ms per detection")
    print(f"   Throughput: {iterations/duration:.0f} detections/second")
    print("\n" + "=" * 60)

# --------------------------
# Run Tests
# --------------------------
if __name__ == "__main__":
    import sys
    
    print("\n" + "="*60)
    print("Detection Service Test Suite")
    print("="*60 + "\n")
    
    print("Available tests:")
    print("  1. Quick test (no dependencies)")
    print("  2. Manual end-to-end test (requires Redis/PostgreSQL)")
    print("  3. Performance test")
    print("  4. Run pytest unit tests")
    
    choice = input("\nSelect test (1-4): ").strip()
    
    if choice == "1":
        asyncio.run(quick_test_detection_only())
    elif choice == "2":
        asyncio.run(manual_test_full_flow())
    elif choice == "3":
        asyncio.run(performance_test())
    elif choice == "4":
        print("\n📦 Installing pytest if needed...")
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install", "pytest", "pytest-asyncio", "-q"])
        print("\n🧪 Running pytest...")
        subprocess.run(["pytest", __file__, "-v", "--tb=short"])
    else:
        print("Invalid choice")
