#!/usr/bin/env python3
"""
Distributed Scanner for enterprise-scale security testing.

This module implements distributed scanning capabilities that can orchestrate
security tests across multiple nodes/machines using Redis as a task queue.
"""

# from __future__ import annotations
# import asyncio
# import json
# import os
# import uuid
# import time
# import logging
# from typing import List, Dict, Any, Optional, Set
# from collections import defaultdict
# import redis
# import psutil
# from concurrent.futures import ThreadPoolExecutor
# import threading

logger = logging.getLogger(__name__)

class DistributedScanner:
    """Distributed scanner that orchestrates scans across multiple nodes."""
    
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379, 
                 redis_db: int = 0, node_id: Optional[str] = None):
        self.node_id = node_id or str(uuid.uuid4())
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
        self.task_queue = f"penai_scans:{self.node_id}"
        self.result_queue = "penai_results"
        self.control_channel = "penai_control"
        self.running = False
        self.max_workers = min(32, (os.cpu_count() or 1) + 4)
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.scan_progress: Dict[str, Dict[str, Any]] = {}
        
    def start_worker(self):
        """Start the distributed scanner worker."""
        logger.info(f"Starting distributed scanner worker {self.node_id}")
        self.running = True
        self._subscribe_to_control_channel()
        
        # Start processing tasks
        while self.running:
            try:
                # Get task from queue
                task_data = self.redis_client.blpop(self.task_queue, timeout=1)
                if task_data:
                    _, task_json = task_data
                    task = json.loads(task_json)
                    self._process_task(task)
            except Exception as e:
                logger.error(f"Error processing task: {e}")
                time.sleep(1)
    
    def _subscribe_to_control_channel(self):
        """Subscribe to control channel for coordination messages."""
        def listen_for_control_messages():
            pubsub = self.redis_client.pubsub()
            pubsub.subscribe(self.control_channel)
            
            for message in pubsub.listen():
                if message['type'] == 'message':
                    try:
                        control_msg = json.loads(message['data'])
                        self._handle_control_message(control_msg)
                    except Exception as e:
                        logger.error(f"Error handling control message: {e}")
        
        control_thread = threading.Thread(target=listen_for_control_messages, daemon=True)
        control_thread.start()
    
    def _handle_control_message(self, message: Dict[str, Any]):
        """Handle control messages from the coordinator."""
        msg_type = message.get("type")
        scan_id = message.get("scan_id")
        
        if msg_type == "cancel_scan" and scan_id:
            if scan_id in self.active_scans:
                logger.info(f"Cancelling scan {scan_id}")
                self.active_scans[scan_id]["cancelled"] = True
    
    def _process_task(self, task: Dict[str, Any]):
        """Process a scanning task."""
        scan_id = task.get("scan_id")
        target = task.get("target")
        scan_config = task.get("config", {})
        
        if not scan_id or not target:
            logger.error("Invalid task: missing scan_id or target")
            return
        
        logger.info(f"Processing scan task {scan_id} for target {target}")
        
        # Track active scan
        self.active_scans[scan_id] = {
            "target": target,
            "start_time": time.time(),
            "cancelled": False
        }
        
        try:
            # Import and run the actual scanner
            findings = self._run_scan(target, scan_config)
            
            # Report results
            result = {
                "scan_id": scan_id,
                "node_id": self.node_id,
                "target": target,
                "findings": findings,
                "status": "completed",
                "duration": time.time() - self.active_scans[scan_id]["start_time"]
            }
            
            self._report_result(result)
        except Exception as e:
            logger.error(f"Error scanning target {target}: {e}")
            result = {
                "scan_id": scan_id,
                "node_id": self.node_id,
                "target": target,
                "error": str(e),
                "status": "failed",
                "duration": time.time() - self.active_scans[scan_id]["start_time"]
            }
            self._report_result(result)
        finally:
            # Clean up
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
    
    def _run_scan(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run the actual security scan on a target."""
        # This would integrate with the existing scanning modules
        # For now, we'll simulate a scan
        findings = []
        
        # In a real implementation, this would call the actual scanners
        # Example:
        # from modules.scanner.xss import xss_check
        # from modules.scanner.sqli import sqli_check
        # findings.extend(await xss_check(target, config.get("outdir", ".")))
        # findings.extend(await sqli_check(target, config.get("outdir", ".")))
        
        # Simulate some findings
        if "vulnweb" in target:
            findings.append({
                "type": "xss-reflected",
                "target": target,
                "severity": 3,
                "confidence": 0.8,
                "description": "Reflected XSS vulnerability found"
            })
        
        return findings
    
    def _report_result(self, result: Dict[str, Any]):
        """Report scan result to the result queue."""
        try:
            result_json = json.dumps(result)
            self.redis_client.rpush(self.result_queue, result_json)
            logger.info(f"Reported result for scan {result['scan_id']}")
        except Exception as e:
            logger.error(f"Error reporting result: {e}")
    
    def submit_scan_batch(self, targets: List[str], config: Dict[str, Any]) -> str:
        """Submit a batch of targets for distributed scanning."""
        scan_id = str(uuid.uuid4())
        
        # Submit each target as a separate task
        for target in targets:
            task = {
                "scan_id": scan_id,
                "target": target,
                "config": config
            }
            
            try:
                task_json = json.dumps(task)
                self.redis_client.rpush(self.task_queue, task_json)
            except Exception as e:
                logger.error(f"Error submitting task for {target}: {e}")
        
        logger.info(f"Submitted scan batch {scan_id} with {len(targets)} targets")
        return scan_id
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get the status of a distributed scan."""
        # Check if scan is active
        if scan_id in self.active_scans:
            return {
                "status": "running",
                "progress": self.scan_progress.get(scan_id, {}),
                "start_time": self.active_scans[scan_id]["start_time"]
            }
        
        # Check Redis for completed results
        results = self._get_scan_results(scan_id)
        if results:
            return {
                "status": "completed",
                "results": results,
                "target_count": len(results)
            }
        
        return {"status": "unknown"}
    
    def _get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get results for a completed scan."""
        results = []
        # In a real implementation, we would query Redis for results
        # This is a simplified version
        return results
    
    def cancel_scan(self, scan_id: str):
        """Cancel a running scan."""
        # Send cancel message to all nodes
        cancel_msg = {
            "type": "cancel_scan",
            "scan_id": scan_id
        }
        
        try:
            self.redis_client.publish(self.control_channel, json.dumps(cancel_msg))
            logger.info(f"Sent cancel message for scan {scan_id}")
        except Exception as e:
            logger.error(f"Error sending cancel message: {e}")
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system metrics for resource monitoring."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "node_id": self.node_id,
                "timestamp": time.time(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available": memory.available,
                "disk_percent": disk.percent,
                "disk_free": disk.free,
                "active_scans": len(self.active_scans),
                "queue_length": self.redis_client.llen(self.task_queue)
            }
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {}

class DistributedScanCoordinator:
    """Coordinator for managing distributed scans across multiple nodes."""
    
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379, redis_db: int = 0):
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
        self.result_queue = "penai_results"
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.scan_results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
    def start_coordinator(self):
        """Start the scan coordinator to collect results."""
        logger.info("Starting distributed scan coordinator")
        
        while True:
            try:
                # Get results from queue
                result_data = self.redis_client.blpop(self.result_queue, timeout=1)
                if result_data:
                    _, result_json = result_data
                    result = json.loads(result_json)
                    self._process_result(result)
            except Exception as e:
                logger.error(f"Error processing result: {e}")
                time.sleep(1)
    
    def _process_result(self, result: Dict[str, Any]):
        """Process a scan result from a worker node."""
        scan_id = result.get("scan_id")
        if not scan_id:
            return
        
        logger.info(f"Processing result for scan {scan_id}")
        self.scan_results[scan_id].append(result)
        
        # Update scan status
        if scan_id in self.active_scans:
            self.active_scans[scan_id]["completed_targets"] += 1
            self.active_scans[scan_id]["findings"].extend(result.get("findings", []))
            
            # Check if scan is complete
            total_targets = self.active_scans[scan_id]["total_targets"]
            completed_targets = self.active_scans[scan_id]["completed_targets"]
            
            if completed_targets >= total_targets:
                self.active_scans[scan_id]["status"] = "completed"
                logger.info(f"Scan {scan_id} completed with {len(self.active_scans[scan_id]['findings'])} findings")
    
    def initiate_distributed_scan(self, targets: List[str], config: Dict[str, Any]) -> str:
        """Initiate a distributed scan across all available nodes."""
        scan_id = str(uuid.uuid4())
        
        # Register the scan
        self.active_scans[scan_id] = {
            "scan_id": scan_id,
            "targets": targets,
            "config": config,
            "total_targets": len(targets),
            "completed_targets": 0,
            "findings": [],
            "start_time": time.time(),
            "status": "running"
        }
        
        # Distribute targets across nodes
        # In a real implementation, we would discover available nodes
        # For now, we'll just submit to the default queue
        self._distribute_targets(scan_id, targets, config)
        
        logger.info(f"Initiated distributed scan {scan_id} with {len(targets)} targets")
        return scan_id
    
    def _distribute_targets(self, scan_id: str, targets: List[str], config: Dict[str, Any]):
        """Distribute targets across available worker nodes."""
        # Simple round-robin distribution for now
        # In a real implementation, we would consider node capacity and load
        for i, target in enumerate(targets):
            task = {
                "scan_id": scan_id,
                "target": target,
                "config": config
            }
            
            try:
                # Distribute to different queues based on hash
                queue_suffix = i % 5  # Distribute across 5 queues
                task_queue = f"penai_scans:queue_{queue_suffix}"
                task_json = json.dumps(task)
                self.redis_client.rpush(task_queue, task_json)
            except Exception as e:
                logger.error(f"Error distributing task for {target}: {e}")
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get results for a distributed scan."""
        if scan_id not in self.active_scans:
            return {"error": "Scan not found"}
        
        scan_info = self.active_scans[scan_id]
        return {
            "scan_id": scan_id,
            "status": scan_info["status"],
            "total_targets": scan_info["total_targets"],
            "completed_targets": scan_info["completed_targets"],
            "findings": scan_info["findings"],
            "duration": time.time() - scan_info["start_time"] if scan_info["status"] == "completed" else None,
            "results_by_node": self.scan_results[scan_id]
        }
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get the status of the entire scanning cluster."""
        try:
            # Get queue lengths
            queue_info = {}
            for i in range(5):
                queue_name = f"penai_scans:queue_{i}"
                queue_info[queue_name] = self.redis_client.llen(queue_name)
            
            return {
                "active_scans": len(self.active_scans),
                "pending_results": self.redis_client.llen(self.result_queue),
                "task_queues": queue_info,
                "nodes": self._discover_nodes()
            }
        except Exception as e:
            logger.error(f"Error getting cluster status: {e}")
            return {}
    
    def _discover_nodes(self) -> List[str]:
        """Discover available worker nodes."""
        # In a real implementation, we would discover nodes through Redis
        # For now, we'll return a static list
        return ["node_1", "node_2", "node_3"]

# Global instances
_distributed_scanner: Optional[DistributedScanner] = None
_distributed_coordinator: Optional[DistributedScanCoordinator] = None

def get_distributed_scanner(redis_host: str = "localhost", redis_port: int = 6379, 
                           redis_db: int = 0, node_id: Optional[str] = None) -> DistributedScanner:
    """Get or create the global distributed scanner instance."""
    global _distributed_scanner
    if _distributed_scanner is None:
        _distributed_scanner = DistributedScanner(redis_host, redis_port, redis_db, node_id)
    return _distributed_scanner

def get_distributed_coordinator(redis_host: str = "localhost", redis_port: int = 6379, 
                              redis_db: int = 0) -> DistributedScanCoordinator:
    """Get or create the global distributed coordinator instance."""
    global _distributed_coordinator
    if _distributed_coordinator is None:
        _distributed_coordinator = DistributedScanCoordinator(redis_host, redis_port, redis_db)
    return _distributed_coordinator

def initiate_distributed_scan(targets: List[str], config: Dict[str, Any]) -> str:
    """Initiate a distributed scan."""
    coordinator = get_distributed_coordinator(
        config.get("redis_host", "localhost"),
        config.get("redis_port", 6379),
        config.get("redis_db", 0)
    )
    return coordinator.initiate_distributed_scan(targets, config)

def get_distributed_scan_results(scan_id: str) -> Dict[str, Any]:
    """Get results for a distributed scan."""
    coordinator = get_distributed_coordinator()
    return coordinator.get_scan_results(scan_id)