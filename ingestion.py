from scapy.all import TCP, UDP, IP, sniff, Raw, rdpcap
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fastapi import FastAPI, Request, HTTPException
import redis.asyncio as redis
import asyncio
import uuid
import json
import logging
import ipaddress
import re
import aiofiles
from pathlib import Path
from typing import Optional
import time
from aiokafka import AIOKafkaConsumer
from aiokafka.errors import KafkaConnectionError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Ingestion Service")
app = FastAPI(title="Ingestion Service")

class LogIngestionService:
	def __init__(self):
		self.redis_client = None
		self.log_buffer = []
		self.buffer_size = 1000
		self.max_buffer_size = 5000 
		self.metrics = {
			"ingested": 0,
			"failed": 0,
			"buffer_flushes": 0
		}
		
	async def start_redis(self):
		self.redis_client = redis.Redis(
			host="localhost", 
			port=6379, 
			decode_responses=True,
			socket_connect_timeout=5,
			socket_keepalive=True,
			retry_on_timeout=True
		)
		
		await self.redis_client.ping()
		
	async def ingest_log(self, log_data: str, source_ip: str, metadata: dict):
		#ingest a log entry with backpressure handling
		if len(self.log_buffer) >= self.max_buffer_size:
			logger.warning(f"Buffer at max capacity ({self.max_buffer_size}), flushing immediately")
			await self._flush_buffer()
			
		job = {
			"threat_id": str(uuid.uuid4()),
			"log_data": log_data,
			"source_ip": source_ip,
			"metadata": metadata,
			"timestamp": time.time()
		}
		self.log_buffer.append(job)
		self.metrics["ingested"] += 1
		
		if len(self.log_buffer) >= self.buffer_size:
			await self._flush_buffer()
			
	async def _flush_buffer(self):
		#flush buffer to Redis with error handling
		if not self.log_buffer:
			return
			
		batch = self.log_buffer.copy()
		self.log_buffer.clear()
		
		try:
			async with self.redis_client.pipeline() as pipe:
				for job in batch:
					pipe.lpush("detection_queue", json.dumps(job))
				await pipe.execute()
			logger.info(f"Flushed {len(batch)} logs to queue")
			self.metrics["buffer_flushes"] += 1
		except redis.RedisError as e:
			logger.error(f"Redis error during flush: {e}")
			
			self.log_buffer.extend(batch)
			self.metrics["failed"] += len(batch)
			
			await self._write_to_dead_letter(batch)
			
	async def _write_to_dead_letter(self, batch):
		#write failed logs to disk for recovery
		try:
			dead_letter_path = Path("dead_letter_queue.jsonl")
			async with aiofiles.open(dead_letter_path, mode='a') as f:
				for job in batch:
					await f.write(json.dumps(job) + "\n")
			logger.info(f"Wrote {len(batch)} failed logs to dead letter queue")
		except Exception as e:
			logger.error(f"Failed to write dead letter queue: {e}")

ingest = LogIngestionService()

def extract_ip(data) -> Optional[str]:
	
	ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
	
	if isinstance(data, dict):
		for k, v in data.items():
			if isinstance(v, str):
				match = re.search(ip_pattern, v)
				if match:
					ip = match.group(0)
					try:
						ipaddress.ip_address(ip)
						return ip
					except ValueError:
						continue
						
	if isinstance(data, str):
		match = re.search(ip_pattern, data)
		if match:
			ip = match.group(0)
			try:
				ipaddress.ip_address(ip)
				return ip
			except ValueError:
				pass
				
	return None

class Handler(FileSystemEventHandler):
	def __init__(self, ingestion):
		self.ingestion = ingestion
		
	def on_modified(self, event):

		if event.is_directory:
			return
			
		path = event.src_path
		if path.endswith('.log'):
			asyncio.create_task(self.process_log(path))
		elif path.endswith('.json'):
			asyncio.create_task(self.process_json(path))
		elif path.endswith('.pcap'):
			asyncio.create_task(self.process_pcap(path))
			
	async def process_log(self, filepath):
		
		try:
			async with aiofiles.open(filepath, mode='r') as f:
				async for line in f:
					line = line.strip()
					if not line:
						continue
					ip = extract_ip(line) or "unknown"
					await self.ingestion.ingest_log(
						log_data=line,
						source_ip=ip,
						metadata={"file": filepath, "type": "log"}
					)
		except Exception as e:
			logger.error(f"Error processing log file {filepath}: {e}")
			
	async def process_json(self, filepath):

		try:
			async with aiofiles.open(filepath, mode='r') as f:
				async for line in f:
					line = line.strip()
					if not line:
						continue
					try:
						content = json.loads(line)
						ip = extract_ip(content) or "unknown"
						await self.ingestion.ingest_log(
							log_data=json.dumps(content),
							source_ip=ip,
							metadata={"file": filepath, "type": "json"}
						)
					except json.JSONDecodeError as e:
						logger.warning(f"Invalid JSON in {filepath}: {e}")
		except Exception as e:
			logger.error(f"Error processing JSON file {filepath}: {e}")
			
	async def process_pcap(self, filepath):
	
		try:
			packets = await asyncio.to_thread(rdpcap, str(filepath))
			for pkt in packets:
				if pkt.haslayer(Raw) and pkt.haslayer(IP):
					try:
						payload = pkt[Raw].load.decode(errors='ignore')
					except:
						continue
						
					ip = pkt[IP].src
					await self.ingestion.ingest_log(
						log_data=payload,
						source_ip=ip,
						metadata={
							"file": filepath,
							"type": "pcap",
							"dst_ip": pkt[IP].dst,
							"protocol": pkt.sprintf("%IP.proto%")
						}
					)
		except Exception as e:
			logger.error(f"Error processing PCAP file {filepath}: {e}")

def start_watcher(ingestion, watch_path="./logs"):
	#Start file system watcher
	event_handler = Handler(ingestion)
	observer = Observer()
	observer.schedule(event_handler, path=watch_path, recursive=True)
	observer.start()
	logger.info(f"File watcher started on {watch_path}")
	return observer

class SyslogProtocol:
	def __init__(self, ingestion):
		self.ingestion = ingestion
		
	def connection_made(self, transport):
		self.transport = transport
		
	def datagram_received(self, data, addr):
		#Handle incoming syslog messages
		try:
			message = data.decode('utf-8', errors='ignore')
			ip, port = addr
			asyncio.create_task(
				self.ingestion.ingest_log(
					log_data=message,
					source_ip=ip,
					metadata={"protocol": "syslog", "port": port}
				)
			)
		except Exception as e:
			logger.error(f"Error processing syslog message: {e}")

async def start_syslog(loop, ingest, port=5140):

	transport, protocol = await loop.create_datagram_endpoint(
		lambda: SyslogProtocol(ingest),
		local_addr=('0.0.0.0', port)
	)
	logger.info(f"Syslog listener started on port {port}")
	return transport, protocol

async def periodic_flush():
	
	while True:
		await asyncio.sleep(60)
		await ingest._flush_buffer()
		logger.info(f"Metrics: {ingest.metrics}")

def start_sniffer(loop):
	
	def callback(pkt):
		asyncio.run_coroutine_threadsafe(handle_packet(pkt), loop)
	sniff(prn=callback, store=False)

async def start_kafka_consumer():
	#Start Kafka consumer with retry logic
	consumer = AIOKafkaConsumer(
		'logs',
		bootstrap_servers='localhost:9092',
		group_id='ingestion-group',
		auto_offset_reset='earliest'
	)
	
	
	max_retries = 5
	retry_delay = 5
	
	for attempt in range(max_retries):
		try:
			await consumer.start()
			logger.info("Kafka Consumer Started Successfully ✅")
			break
		except KafkaConnectionError as e:
			if attempt < max_retries - 1:
				logger.warning(f"Kafka connection failed (attempt {attempt + 1}/{max_retries}), retrying in {retry_delay}s...")
				await asyncio.sleep(retry_delay)
			else:
				logger.error(f"Failed to connect to Kafka after {max_retries} attempts: {e}")
				return
	
	try:
		async for msg in consumer:
			#Process Kafka messages and forward to Redis queue
			try:
				log_data = json.loads(msg.value.decode('utf-8'))
				await ingest.ingest_log(
					log_data=log_data.get('log', str(log_data)),
					source_ip=log_data.get('source_ip', 'kafka'),
					metadata={"source": "kafka", "topic": msg.topic, "partition": msg.partition}
				)
			except Exception as e:
				logger.error(f"Error processing Kafka message: {e}")
	finally:
		await consumer.stop()

@app.on_event("startup")
async def on_startup():
	
	loop = asyncio.get_event_loop()
	
	
	try:
		Path("./logs").mkdir(exist_ok=True)
		start_watcher(ingest, "./logs")
		logger.info("File watcher started")
	except Exception as e:
		logger.error(f"Failed to start file watcher: {e}")
	
	
	try:
		await ingest.start_redis()
		logger.info("Redis connection successful")
	except Exception as e:
		logger.error(f"Redis connection failed: {e}")
		raise
	
	
	try:
		asyncio.create_task(periodic_flush())
		logger.info("Buffer flush task started (every 60s)")
	except Exception as e:
		logger.error(f"Failed to start buffer flush: {e}")
	
	
	try:
		await start_syslog(loop, ingest, port=5140)
	except Exception as e:
		logger.warning(f"Failed to start syslog listener: {e}")
	
	
	try:
		asyncio.create_task(asyncio.to_thread(start_sniffer, loop))
		logger.info("Packet sniffer started ✅")
	except Exception as e:
		logger.warning(f"Failed to start sniffer (requires elevated permissions): {e} ⚠️")
	
	
	try:
		asyncio.create_task(start_kafka_consumer())
	except Exception as e:
		logger.warning(f"Failed to start Kafka consumer: {e}")

@app.post("/ingest/http")
async def ingest_http_log(request: Request):
	#HTTP endpoint for log ingestion
	try:
		body = await request.json()
		
		if "log" not in body:
			raise HTTPException(status_code=400, detail="Missing 'log' field")
		
		await ingest.ingest_log(
			log_data=body["log"],
			source_ip=body.get("ip", request.client.host),
			metadata=body.get("metadata", {}),
		)
		return {"status": "ingested", "threat_id": str(uuid.uuid4())}
	except json.JSONDecodeError:
		raise HTTPException(status_code=400, detail="Invalid JSON")
	except Exception as e:
		logger.error(f"Error ingesting HTTP log: {e}")
		raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/metrics")
async def get_metrics():
	
	return {
		"metrics": ingest.metrics,
		"buffer_size": len(ingest.log_buffer),
		"redis_connected": ingest.redis_client is not None
	}

@app.on_event("shutdown")
async def shutdown():
	
	await ingest._flush_buffer()
	if ingest.redis_client:
		await ingest.redis_client.close()
	logger.info("Ingestion Service Shutdown Successfully ✅")
