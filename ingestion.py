

from fastapi import FastAPI, Request
import asyncio
import aiofiles
import redis.asyncio as redis
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import uuid
import json
import logging

logging.basicConfig(
	level=logging.INFO
)

logger = logging.getLogger("Ingestion Service")
app = FastAPI(title="Ingestion Service")

class LogIngestionService:
    def __init__(self):
        self.redis_client = None
        self.log_buffer = []
        self.buffer_size = 1000
    
    async def start_redis():
	    self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
    
    async def ingest_log(self, log_data: str, source_ip: str, metadata: dict):
        """Ingest a single log entry"""
        job = {
            "threat_id": str(uuid.uuid4()),
            "log_data": log_data,
            "source_ip": source_ip,
            "metadata": metadata
        }
        
        # Buffer for batch insertion
        self.log_buffer.append(job)
        
        if len(self.log_buffer) >= self.buffer_size:
            await self._flush_buffer()
    
    async def _flush_buffer(self):
        """Flush buffered logs to detection queue"""
        if not self.log_buffer:
            return
        
        # Batch push to Redis
        pipeline = self.redis_client.pipeline()
        for job in self.log_buffer:
            pipeline.lpush("detection_queue", json.dumps(job))
        await pipeline.execute()
        
        logger.info(f"Flushed {len(self.log_buffer)} logs to queue")
        self.log_buffer.clear()
        
 
        
async def flush():
    while True:    
        await asyncio.sleep(60)
	    await ingestion_service._flush_buffer()
asyncio.create_task(flush())


        	
@app.post("/ingest/http")
async def ingest_http_log(request: Request):
    """HTTP endpoint for log ingestion"""
    body = await request.json()
    
    await ingestion_service.ingest_log(
        log_data=body["log"],
        source_ip=body.get("ip", request.client.host),
        metadata=body.get("metadata", {})
    )
    
    return {"status": "ingested"}
    
    
    
from fastapi import FastAPI, Request
import redis.asyncio as redis
import asyncio
import uuid
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Ingestion Service")

app = FastAPI(title="Ingestion Service")


class LogIngestionService:
    def __init__(self):
        self.redis_client = None
        self.log_buffer = []
        self.buffer_size = 1000

    async def start_redis(self):
        self.redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

    async def ingest_log(self, log_data: str, source_ip: str, metadata: dict):
        job = {
            "threat_id": str(uuid.uuid4()),
            "log_data": log_data,
            "source_ip": source_ip,
            "metadata": metadata,
        }
        self.log_buffer.append(job)
        if len(self.log_buffer) >= self.buffer_size:
            await self._flush_buffer()

    async def _flush_buffer(self):
        if not self.log_buffer:
            return
        async with self.redis_client.pipeline() as pipe:
            for job in self.log_buffer:
                await pipe.lpush("detection_queue", json.dumps(job))
            await pipe.execute()
        logger.info(f"Flushed {len(self.log_buffer)} logs to queue")
        self.log_buffer.clear()


ingest = LogIngestionService()


async def flush():
    while True:
        await asyncio.sleep(60)
        await ingest._flush_buffer()


@app.on_event("startup")
async def on_startup():
    await ingest.start_redis()
    asyncio.create_task(flush())

@app.on_event("shutdown")
async def on_shutdown():
	

@app.post("/ingest/http")
async def ingest_http_log(request: Request):
    body = await request.json()
    await ingest.ingest_log(
        log_data=body["log"],
        source_ip=body.get("ip", request.client.host),
        metadata=body.get("metadata", {}),
    )
    return {"status": "ingested"}




	
	
	
	




    
    

	

		
	
		





			
		

