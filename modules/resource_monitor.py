"""
Resource Monitor for comprehensive system resource tracking during scans.

This module implements resource monitoring and optimization features to track
CPU, memory, and I/O usage during security scans.
"""

from __future__ import annotations
import psutil
import time
import json
import os
import threading
import logging
from typing import Dict, Any, List, Optional
from collections import deque
import asyncio

logger = logging.getLogger(__name__)

class ResourceMonitor:
    """Monitors and optimizes system resource usage during scans."""
    
    def __init__(self, monitoring_interval: float = 1.0):
        self.monitoring_interval = monitoring_interval
        self.monitoring = False
        self.metrics_history = deque(maxlen=1000)  # Keep last 1000 metrics
        self.alert_thresholds = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_percent": 90.0
        }
        self.resource_alerts: List[Dict[str, Any]] = []
        self.optimization_callbacks: List[Any] = []
        self.monitoring_thread: Optional[threading.Thread] = None
        
    def start_monitoring(self):
        """Start resource monitoring in a background thread."""
        if self.monitoring:
            return
            
        logger.info("Starting resource monitoring")
        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop resource monitoring."""
        logger.info("Stopping resource monitoring")
        self.monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Check for alerts
                self._check_alerts(metrics)
                
                # Trigger optimization callbacks if needed
                self._trigger_optimizations(metrics)
                
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect system resource metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            net_io = psutil.net_io_counters()
            
            # Process metrics
            current_process = psutil.Process()
            process_cpu = current_process.cpu_percent()
            process_memory = current_process.memory_info()
            
            return {
                "timestamp": time.time(),
                "cpu": {
                    "percent": cpu_percent,
                    "frequency": cpu_freq.current if cpu_freq else None,
                    "cores": psutil.cpu_count()
                },
                "memory": {
                    "percent": memory.percent,
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used
                },
                "disk": {
                    "percent": disk.percent,
                    "total": disk.total,
                    "free": disk.free,
                    "used": disk.used
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                },
                "process": {
                    "cpu_percent": process_cpu,
                    "memory_rss": process_memory.rss,
                    "memory_vms": process_memory.vms,
                    "num_threads": current_process.num_threads()
                }
            }
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return {"timestamp": time.time(), "error": str(e)}
    
    def _check_alerts(self, metrics: Dict[str, Any]):
        """Check for resource usage alerts."""
        try:
            # CPU alert
            cpu_percent = metrics.get("cpu", {}).get("percent", 0)
            if cpu_percent > self.alert_thresholds["cpu_percent"]:
                alert = {
                    "type": "high_cpu",
                    "timestamp": metrics["timestamp"],
                    "value": cpu_percent,
                    "threshold": self.alert_thresholds["cpu_percent"]
                }
                self.resource_alerts.append(alert)
                logger.warning(f"High CPU usage detected: {cpu_percent}%")
            
            # Memory alert
            memory_percent = metrics.get("memory", {}).get("percent", 0)
            if memory_percent > self.alert_thresholds["memory_percent"]:
                alert = {
                    "type": "high_memory",
                    "timestamp": metrics["timestamp"],
                    "value": memory_percent,
                    "threshold": self.alert_thresholds["memory_percent"]
                }
                self.resource_alerts.append(alert)
                logger.warning(f"High memory usage detected: {memory_percent}%")
            
            # Disk alert
            disk_percent = metrics.get("disk", {}).get("percent", 0)
            if disk_percent > self.alert_thresholds["disk_percent"]:
                alert = {
                    "type": "high_disk",
                    "timestamp": metrics["timestamp"],
                    "value": disk_percent,
                    "threshold": self.alert_thresholds["disk_percent"]
                }
                self.resource_alerts.append(alert)
                logger.warning(f"High disk usage detected: {disk_percent}%")
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")
    
    def _trigger_optimizations(self, metrics: Dict[str, Any]):
        """Trigger optimization callbacks based on resource usage."""
        try:
            # Check if any thresholds are exceeded
            cpu_percent = metrics.get("cpu", {}).get("percent", 0)
            memory_percent = metrics.get("memory", {}).get("percent", 0)
            disk_percent = metrics.get("disk", {}).get("percent", 0)
            
            high_resource_usage = (
                cpu_percent > self.alert_thresholds["cpu_percent"] or
                memory_percent > self.alert_thresholds["memory_percent"] or
                disk_percent > self.alert_thresholds["disk_percent"]
            )
            
            if high_resource_usage:
                for callback in self.optimization_callbacks:
                    try:
                        callback(metrics)
                    except Exception as e:
                        logger.error(f"Error in optimization callback: {e}")
        except Exception as e:
            logger.error(f"Error triggering optimizations: {e}")
    
    def add_optimization_callback(self, callback: Any):
        """Add a callback to be triggered when resource usage is high."""
        self.optimization_callbacks.append(callback)
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get the most recent resource metrics."""
        if self.metrics_history:
            return self.metrics_history[-1]
        return {}
    
    def get_metrics_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get historical resource metrics."""
        if limit:
            return list(self.metrics_history)[-limit:]
        return list(self.metrics_history)
    
    def get_resource_alerts(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get resource usage alerts."""
        if limit:
            return self.resource_alerts[-limit:]
        return self.resource_alerts.copy()
    
    def get_system_summary(self) -> Dict[str, Any]:
        """Get a summary of current system resource usage."""
        metrics = self.get_current_metrics()
        if not metrics:
            return {}
        
        return {
            "timestamp": metrics.get("timestamp"),
            "cpu_usage": metrics.get("cpu", {}).get("percent", 0),
            "memory_usage": metrics.get("memory", {}).get("percent", 0),
            "disk_usage": metrics.get("disk", {}).get("percent", 0),
            "process_cpu": metrics.get("process", {}).get("cpu_percent", 0),
            "process_memory_mb": metrics.get("process", {}).get("memory_rss", 0) / (1024 * 1024),
            "alerts_count": len(self.resource_alerts)
        }
    
    def export_metrics(self, filepath: str):
        """Export metrics history to a JSON file."""
        try:
            metrics_data = {
                "metrics_history": self.get_metrics_history(),
                "alerts": self.get_resource_alerts(),
                "export_timestamp": time.time()
            }
            
            with open(filepath, 'w') as f:
                json.dump(metrics_data, f, indent=2)
            
            logger.info(f"Exported metrics to {filepath}")
        except Exception as e:
            logger.error(f"Error exporting metrics: {e}")
    
    def set_alert_thresholds(self, thresholds: Dict[str, float]):
        """Set custom alert thresholds."""
        self.alert_thresholds.update(thresholds)
        logger.info(f"Updated alert thresholds: {self.alert_thresholds}")

class AdaptiveResourceOptimizer:
    """Adaptive optimizer that adjusts scan parameters based on resource usage."""
    
    def __init__(self, resource_monitor: ResourceMonitor):
        self.resource_monitor = resource_monitor
        self.resource_monitor.add_optimization_callback(self._optimize_resources)
        self.optimization_history: List[Dict[str, Any]] = []
        
    def _optimize_resources(self, metrics: Dict[str, Any]):
        """Optimize resource usage based on current metrics."""
        try:
            optimization_actions = []
            
            # CPU-based optimizations
            cpu_percent = metrics.get("cpu", {}).get("percent", 0)
            if cpu_percent > 85:
                optimization_actions.append({
                    "action": "reduce_parallel_scans",
                    "reason": f"High CPU usage ({cpu_percent}%)",
                    "severity": "high"
                })
            
            # Memory-based optimizations
            memory_percent = metrics.get("memory", {}).get("percent", 0)
            if memory_percent > 80:
                optimization_actions.append({
                    "action": "reduce_memory_cache",
                    "reason": f"High memory usage ({memory_percent}%)",
                    "severity": "high"
                })
            
            # Disk-based optimizations
            disk_percent = metrics.get("disk", {}).get("percent", 0)
            if disk_percent > 85:
                optimization_actions.append({
                    "action": "reduce_output_writes",
                    "reason": f"High disk usage ({disk_percent}%)",
                    "severity": "medium"
                })
            
            if optimization_actions:
                # Log optimization actions
                for action in optimization_actions:
                    logger.info(f"Resource optimization: {action['action']} - {action['reason']}")
                
                # Store optimization history
                self.optimization_history.append({
                    "timestamp": metrics["timestamp"],
                    "actions": optimization_actions,
                    "metrics": metrics
                })
                
                # In a real implementation, we would trigger actual optimizations
                # For example:
                # - Reduce parallel scan workers
                # - Clear caches
                # - Adjust scan intensity
                # - Throttle network requests
                
        except Exception as e:
            logger.error(f"Error in resource optimization: {e}")
    
    def get_optimization_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get history of optimization actions."""
        if limit:
            return self.optimization_history[-limit:]
        return self.optimization_history.copy()

# Global instances
_resource_monitor: Optional[ResourceMonitor] = None
_adaptive_optimizer: Optional[AdaptiveResourceOptimizer] = None

def get_resource_monitor(monitoring_interval: float = 1.0) -> ResourceMonitor:
    """Get or create the global resource monitor instance."""
    global _resource_monitor
    if _resource_monitor is None:
        _resource_monitor = ResourceMonitor(monitoring_interval)
    return _resource_monitor

def get_adaptive_optimizer() -> AdaptiveResourceOptimizer:
    """Get or create the global adaptive optimizer instance."""
    global _adaptive_optimizer
    if _adaptive_optimizer is None:
        monitor = get_resource_monitor()
        _adaptive_optimizer = AdaptiveResourceOptimizer(monitor)
    return _adaptive_optimizer

def start_resource_monitoring(monitoring_interval: float = 1.0):
    """Start resource monitoring."""
    monitor = get_resource_monitor(monitoring_interval)
    monitor.start_monitoring()

def stop_resource_monitoring():
    """Stop resource monitoring."""
    monitor = get_resource_monitor()
    monitor.stop_monitoring()

def get_system_summary() -> Dict[str, Any]:
    """Get current system resource summary."""
    monitor = get_resource_monitor()
    return monitor.get_system_summary()