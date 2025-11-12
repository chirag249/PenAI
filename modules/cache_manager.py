#!/usr/bin/env python3
"""
Cache Manager for intelligent caching of scan results.

This module implements intelligent caching mechanisms to store and reuse
results from previous scans, reducing redundant operations and improving
scan times.
"""

from __future__ import annotations
import json
import os
import hashlib
import time
import logging
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import pickle
from collections import OrderedDict

logger = logging.getLogger(__name__)

class IntelligentCache:
    """Intelligent cache manager for storing and retrieving scan results."""
    
    def __init__(self, cache_dir: str = "cache", max_size_mb: int = 100):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.max_size_mb = max_size_mb
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.cache_metadata = self._load_metadata()
        self.access_order = OrderedDict()  # For LRU tracking
        self._load_access_order()
        
    def _load_metadata(self) -> Dict[str, Any]:
        """Load cache metadata from file."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Error loading cache metadata: {e}")
                return {}
        return {"entries": {}, "total_size": 0}
    
    def _save_metadata(self):
        """Save cache metadata to file."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.cache_metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cache metadata: {e}")
    
    def _load_access_order(self):
        """Load access order for LRU tracking."""
        access_file = self.cache_dir / "access_order.json"
        if access_file.exists():
            try:
                with open(access_file, 'r') as f:
                    data = json.load(f)
                    self.access_order = OrderedDict(data)
            except Exception as e:
                logger.warning(f"Error loading access order: {e}")
    
    def _save_access_order(self):
        """Save access order for LRU tracking."""
        access_file = self.cache_dir / "access_order.json"
        try:
            # Keep only the most recent 1000 entries
            recent_entries = list(self.access_order.items())[-1000:]
            with open(access_file, 'w') as f:
                json.dump(recent_entries, f)
        except Exception as e:
            logger.error(f"Error saving access order: {e}")
    
    def _get_cache_key(self, target: str, scan_type: str, params: Dict[str, Any]) -> str:
        """Generate a cache key for a scan request."""
        # Create a hash of the target, scan type, and parameters
        key_data = {
            "target": target,
            "scan_type": scan_type,
            "params": params
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def get(self, target: str, scan_type: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached results for a scan request."""
        cache_key = self._get_cache_key(target, scan_type, params)
        
        # Check if entry exists
        if cache_key not in self.cache_metadata["entries"]:
            return None
        
        # Check if cache entry is still valid
        entry = self.cache_metadata["entries"][cache_key]
        if self._is_expired(entry):
            self._remove_expired_entry(cache_key)
            return None
        
        # Get cache file path
        cache_file = self.cache_dir / f"{cache_key}.cache"
        if not cache_file.exists():
            # Cache file missing, remove metadata entry
            self._remove_entry(cache_key)
            return None
        
        try:
            # Update access order (LRU)
            self.access_order[cache_key] = time.time()
            self._save_access_order()
            
            # Load cached data
            with open(cache_file, 'rb') as f:
                cached_data = pickle.load(f)
            
            logger.debug(f"Cache hit for {target} ({scan_type})")
            return cached_data
        except Exception as e:
            logger.error(f"Error loading cached data: {e}")
            # Remove corrupted cache entry
            self._remove_entry(cache_key)
            return None
    
    def put(self, target: str, scan_type: str, params: Dict[str, Any], 
            results: Dict[str, Any], ttl_seconds: int = 86400) -> bool:
        """Store scan results in cache."""
        cache_key = self._get_cache_key(target, scan_type, params)
        cache_file = self.cache_dir / f"{cache_key}.cache"
        
        try:
            # Serialize and save results
            with open(cache_file, 'wb') as f:
                pickle.dump(results, f)
            
            # Get file size
            file_size = cache_file.stat().st_size
            
            # Update metadata
            entry = {
                "target": target,
                "scan_type": scan_type,
                "params": params,
                "created": time.time(),
                "expires": time.time() + ttl_seconds,
                "size": file_size,
                "access_count": 0
            }
            
            # Update total size
            old_size = self.cache_metadata["entries"].get(cache_key, {}).get("size", 0)
            self.cache_metadata["total_size"] += file_size - old_size
            
            # Update entry
            self.cache_metadata["entries"][cache_key] = entry
            
            # Update access order
            self.access_order[cache_key] = time.time()
            
            # Save metadata
            self._save_metadata()
            self._save_access_order()
            
            # Check size limits and cleanup if needed
            self._enforce_size_limit()
            
            logger.debug(f"Cached results for {target} ({scan_type})")
            return True
        except Exception as e:
            logger.error(f"Error caching results: {e}")
            return False
    
    def _is_expired(self, entry: Dict[str, Any]) -> bool:
        """Check if a cache entry has expired."""
        return time.time() > entry.get("expires", 0)
    
    def _remove_expired_entry(self, cache_key: str):
        """Remove an expired cache entry."""
        self._remove_entry(cache_key)
    
    def _remove_entry(self, cache_key: str):
        """Remove a cache entry."""
        # Remove cache file
        cache_file = self.cache_dir / f"{cache_key}.cache"
        if cache_file.exists():
            try:
                file_size = cache_file.stat().st_size
                cache_file.unlink()
                self.cache_metadata["total_size"] -= file_size
            except Exception as e:
                logger.error(f"Error removing cache file: {e}")
        
        # Remove from metadata
        if cache_key in self.cache_metadata["entries"]:
            del self.cache_metadata["entries"][cache_key]
        
        # Remove from access order
        if cache_key in self.access_order:
            del self.access_order[cache_key]
        
        # Save updated metadata
        self._save_metadata()
        self._save_access_order()
    
    def _enforce_size_limit(self):
        """Enforce cache size limits using LRU eviction."""
        current_size_mb = self.cache_metadata["total_size"] / (1024 * 1024)
        
        if current_size_mb <= self.max_size_mb:
            return
        
        # Sort entries by access time (LRU)
        sorted_entries = sorted(self.access_order.items(), key=lambda x: x[1])
        
        # Remove oldest entries until under size limit
        for cache_key, _ in sorted_entries:
            if current_size_mb <= self.max_size_mb:
                break
            
            if cache_key in self.cache_metadata["entries"]:
                entry_size = self.cache_metadata["entries"][cache_key]["size"]
                self._remove_entry(cache_key)
                current_size_mb -= entry_size / (1024 * 1024)
    
    def invalidate(self, target: Optional[str] = None, scan_type: Optional[str] = None):
        """Invalidate cache entries."""
        if target is None and scan_type is None:
            # Clear entire cache
            self._clear_cache()
            return
        
        # Find entries to invalidate
        keys_to_remove = []
        for cache_key, entry in self.cache_metadata["entries"].items():
            should_remove = True
            
            if target and entry["target"] != target:
                should_remove = False
            
            if scan_type and entry["scan_type"] != scan_type:
                should_remove = False
            
            if should_remove:
                keys_to_remove.append(cache_key)
        
        # Remove entries
        for cache_key in keys_to_remove:
            self._remove_entry(cache_key)
    
    def _clear_cache(self):
        """Clear the entire cache."""
        try:
            # Remove all cache files
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink()
            
            # Clear metadata
            self.cache_metadata = {"entries": {}, "total_size": 0}
            self.access_order = OrderedDict()
            
            # Save empty metadata
            self._save_metadata()
            self._save_access_order()
            
            logger.info("Cache cleared")
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_entries = len(self.cache_metadata["entries"])
        total_size_mb = self.cache_metadata["total_size"] / (1024 * 1024)
        
        # Calculate hit rate if we have access data
        total_accesses = sum(entry.get("access_count", 0) for entry in self.cache_metadata["entries"].values())
        
        return {
            "total_entries": total_entries,
            "total_size_mb": round(total_size_mb, 2),
            "max_size_mb": self.max_size_mb,
            "hit_rate": "N/A",  # Would need to track hits vs misses
            "oldest_entry": min((entry["created"] for entry in self.cache_metadata["entries"].values()), default=None),
            "newest_entry": max((entry["created"] for entry in self.cache_metadata["entries"].values()), default=None)
        }
    
    def get_cached_targets(self) -> List[str]:
        """Get list of cached targets."""
        targets = set()
        for entry in self.cache_metadata["entries"].values():
            targets.add(entry["target"])
        return list(targets)

# Global cache instance
_intelligent_cache: Optional[IntelligentCache] = None

def get_intelligent_cache(cache_dir: str = "cache", max_size_mb: int = 100) -> IntelligentCache:
    """Get or create the global intelligent cache instance."""
    global _intelligent_cache
    if _intelligent_cache is None:
        _intelligent_cache = IntelligentCache(cache_dir, max_size_mb)
    return _intelligent_cache

def get_cached_results(target: str, scan_type: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get cached results for a scan."""
    cache = get_intelligent_cache()
    return cache.get(target, scan_type, params)

def cache_results(target: str, scan_type: str, params: Dict[str, Any], 
                 results: Dict[str, Any], ttl_seconds: int = 86400) -> bool:
    """Cache scan results."""
    cache = get_intelligent_cache()
    return cache.put(target, scan_type, params, results, ttl_seconds)

def invalidate_cache(target: Optional[str] = None, scan_type: Optional[str] = None):
    """Invalidate cache entries."""
    cache = get_intelligent_cache()
    cache.invalidate(target, scan_type)