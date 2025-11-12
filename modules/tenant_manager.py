#!/usr/bin/env python3
"""
Tenant Manager for multi-tenant security testing environments.

This module implements multi-tenant support allowing isolated scanning
environments for different teams or clients within the same deployment.
"""

from __future__ import annotations
import os
import json
import uuid
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class Tenant:
    """Represents a tenant in the multi-tenant system."""
    id: str
    name: str
    created_at: str
    config: Dict[str, Any]
    allowed_targets: List[str]
    scan_limit: int
    active: bool = True

class TenantManager:
    """Manages multi-tenant environments for isolated scanning."""
    
    def __init__(self, tenants_dir: str = "tenants"):
        self.tenants_dir = Path(tenants_dir)
        self.tenants_dir.mkdir(exist_ok=True)
        self.tenants_file = self.tenants_dir / "tenants.json"
        self.tenants: Dict[str, Tenant] = self._load_tenants()
        
    def _load_tenants(self) -> Dict[str, Tenant]:
        """Load tenants from file."""
        if self.tenants_file.exists():
            try:
                with open(self.tenants_file, 'r') as f:
                    tenants_data = json.load(f)
                
                tenants = {}
                for tenant_id, tenant_data in tenants_data.items():
                    # Convert dict to Tenant object
                    tenant = Tenant(**tenant_data)
                    tenants[tenant_id] = tenant
                return tenants
            except Exception as e:
                logger.error(f"Error loading tenants: {e}")
                return {}
        return {}
    
    def _save_tenants(self):
        """Save tenants to file."""
        try:
            # Convert Tenant objects to dicts
            tenants_data = {}
            for tenant_id, tenant in self.tenants.items():
                tenants_data[tenant_id] = asdict(tenant)
            
            with open(self.tenants_file, 'w') as f:
                json.dump(tenants_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving tenants: {e}")
    
    def create_tenant(self, name: str, config: Optional[Dict[str, Any]] = None, 
                     allowed_targets: Optional[List[str]] = None, scan_limit: int = 100) -> str:
        """Create a new tenant."""
        tenant_id = str(uuid.uuid4())
        
        tenant = Tenant(
            id=tenant_id,
            name=name,
            created_at=datetime.now().isoformat(),
            config=config or {},
            allowed_targets=allowed_targets or [],
            scan_limit=scan_limit
        )
        
        self.tenants[tenant_id] = tenant
        self._save_tenants()
        
        # Create tenant directory
        tenant_dir = self.tenants_dir / tenant_id
        tenant_dir.mkdir(exist_ok=True)
        
        logger.info(f"Created tenant {name} with ID {tenant_id}")
        return tenant_id
    
    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get a tenant by ID."""
        return self.tenants.get(tenant_id)
    
    def list_tenants(self) -> List[Tenant]:
        """List all tenants."""
        return list(self.tenants.values())
    
    def update_tenant(self, tenant_id: str, **kwargs) -> bool:
        """Update tenant properties."""
        if tenant_id not in self.tenants:
            return False
        
        tenant = self.tenants[tenant_id]
        
        # Update allowed fields
        updatable_fields = ["name", "config", "allowed_targets", "scan_limit", "active"]
        for field, value in kwargs.items():
            if field in updatable_fields:
                setattr(tenant, field, value)
        
        self.tenants[tenant_id] = tenant
        self._save_tenants()
        return True
    
    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant."""
        if tenant_id not in self.tenants:
            return False
        
        tenant = self.tenants[tenant_id]
        tenant_name = tenant.name
        
        # Remove from memory
        del self.tenants[tenant_id]
        self._save_tenants()
        
        # Remove tenant directory
        tenant_dir = self.tenants_dir / tenant_id
        if tenant_dir.exists():
            import shutil
            try:
                shutil.rmtree(tenant_dir)
                logger.info(f"Removed tenant directory for {tenant_name}")
            except Exception as e:
                logger.error(f"Error removing tenant directory: {e}")
        
        logger.info(f"Deleted tenant {tenant_name}")
        return True
    
    def is_target_allowed(self, tenant_id: str, target: str) -> bool:
        """Check if a target is allowed for a tenant."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return False
        
        if not tenant.active:
            return False
        
        # If no allowed targets specified, allow all
        if not tenant.allowed_targets:
            return True
        
        # Check if target matches any allowed pattern
        for allowed_target in tenant.allowed_targets:
            if self._matches_target_pattern(target, allowed_target):
                return True
        
        return False
    
    def _matches_target_pattern(self, target: str, pattern: str) -> bool:
        """Check if a target matches an allowed pattern."""
        # Simple pattern matching - could be enhanced with regex
        if pattern == "*":
            return True
        
        if target.startswith(pattern):
            return True
        
        if pattern in target:
            return True
        
        return False
    
    def get_tenant_scan_dir(self, tenant_id: str, scan_id: str) -> str:
        """Get the scan directory for a tenant."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        if not tenant.active:
            raise ValueError(f"Tenant {tenant_id} is not active")
        
        tenant_scan_dir = self.tenants_dir / tenant_id / "scans" / scan_id
        tenant_scan_dir.mkdir(parents=True, exist_ok=True)
        return str(tenant_scan_dir)
    
    def get_tenant_config(self, tenant_id: str) -> Dict[str, Any]:
        """Get configuration for a tenant."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return {}
        
        return tenant.config or {}

class TenantAwareScanner:
    """Scanner that respects tenant boundaries and limits."""
    
    def __init__(self, tenant_manager: TenantManager):
        self.tenant_manager = tenant_manager
        self.tenant_scans: Dict[str, Dict[str, Any]] = {}  # tenant_id -> {scan_id -> scan_info}
    
    def validate_scan_request(self, tenant_id: str, targets: List[str]) -> bool:
        """Validate that a scan request is allowed for the tenant."""
        # Check if tenant exists and is active
        tenant = self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            logger.error(f"Tenant {tenant_id} not found")
            return False
        
        if not tenant.active:
            logger.error(f"Tenant {tenant_id} is not active")
            return False
        
        # Check target permissions
        for target in targets:
            if not self.tenant_manager.is_target_allowed(tenant_id, target):
                logger.error(f"Target {target} not allowed for tenant {tenant_id}")
                return False
        
        # Check scan limit
        tenant_scan_count = len(self.tenant_scans.get(tenant_id, {}))
        if tenant_scan_count >= tenant.scan_limit:
            logger.error(f"Tenant {tenant_id} has reached scan limit of {tenant.scan_limit}")
            return False
        
        return True
    
    def register_scan(self, tenant_id: str, scan_id: str, targets: List[str]):
        """Register a scan for a tenant."""
        if tenant_id not in self.tenant_scans:
            self.tenant_scans[tenant_id] = {}
        
        self.tenant_scans[tenant_id][scan_id] = {
            "scan_id": scan_id,
            "targets": targets,
            "started_at": datetime.now().isoformat(),
            "status": "running"
        }
    
    def update_scan_status(self, tenant_id: str, scan_id: str, status: str):
        """Update the status of a tenant scan."""
        if tenant_id in self.tenant_scans and scan_id in self.tenant_scans[tenant_id]:
            self.tenant_scans[tenant_id][scan_id]["status"] = status
    
    def get_tenant_scans(self, tenant_id: str) -> Dict[str, Any]:
        """Get all scans for a tenant."""
        return self.tenant_scans.get(tenant_id, {})

# Global instances
_tenant_manager: Optional[TenantManager] = None
_tenant_aware_scanner: Optional[TenantAwareScanner] = None

def get_tenant_manager(tenants_dir: str = "tenants") -> TenantManager:
    """Get or create the global tenant manager instance."""
    global _tenant_manager
    if _tenant_manager is None:
        _tenant_manager = TenantManager(tenants_dir)
    return _tenant_manager

def get_tenant_aware_scanner() -> TenantAwareScanner:
    """Get or create the global tenant aware scanner instance."""
    global _tenant_aware_scanner
    if _tenant_aware_scanner is None:
        tenant_manager = get_tenant_manager()
        _tenant_aware_scanner = TenantAwareScanner(tenant_manager)
    return _tenant_aware_scanner

def create_tenant(name: str, config: Optional[Dict[str, Any]] = None, 
                 allowed_targets: Optional[List[str]] = None, scan_limit: int = 100) -> str:
    """Create a new tenant."""
    tenant_manager = get_tenant_manager()
    return tenant_manager.create_tenant(name, config, allowed_targets, scan_limit)

def get_tenant(tenant_id: str) -> Optional[Tenant]:
    """Get a tenant by ID."""
    tenant_manager = get_tenant_manager()
    return tenant_manager.get_tenant(tenant_id)

def validate_tenant_scan(tenant_id: str, targets: List[str]) -> bool:
    """Validate that a scan is allowed for a tenant."""
    scanner = get_tenant_aware_scanner()
    return scanner.validate_scan_request(tenant_id, targets)