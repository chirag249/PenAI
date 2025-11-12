#!/usr/bin/env python3
"""
Access Control Module for PenAI

This module provides role-based access control (RBAC) and multi-factor authentication (MFA)
capabilities for the system.
"""

import os
import json
import hashlib
import time
import base64
import secrets
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from datetime import datetime, timedelta

class AccessControlManager:
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the access control manager.
        
        Args:
            config_path: Optional path to access control configuration file
        """
        self.config_path = config_path or "access_control_config.json"
        self.users = {}
        self.roles = {}
        self.permissions = {}
        self.sessions = {}
        self.mfa_enabled = False
        self.mfa_methods = ["totp", "email", "sms"]
        
        # Load configuration if it exists
        self._load_config()

    def _load_config(self):
        """Load access control configuration from file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    self.users = config.get("users", {})
                    self.roles = config.get("roles", {})
                    self.permissions = config.get("permissions", {})
                    self.mfa_enabled = config.get("mfa_enabled", False)
            except Exception:
                pass

    def _save_config(self):
        """Save access control configuration to file."""
        config = {
            "users": self.users,
            "roles": self.roles,
            "permissions": self.permissions,
            "mfa_enabled": self.mfa_enabled
        }
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

    def create_user(self, username: str, password: str, roles: Optional[List[str]] = None, 
                   email: Optional[str] = None, mfa_enabled: bool = False) -> bool:
        """
        Create a new user account.
        
        Args:
            username: Username for the account
            password: Password for the account
            roles: List of roles to assign to the user
            email: Optional email for MFA
            mfa_enabled: Whether MFA is enabled for this user
            
        Returns:
            True if successful, False otherwise
        """
        if username in self.users:
            return False
            
        # Hash password
        salt = secrets.token_bytes(32)
        password_hash = self._hash_password(password, salt)
        
        self.users[username] = {
            "password_hash": base64.b64encode(password_hash).decode(),
            "salt": base64.b64encode(salt).decode(),
            "roles": roles or [],
            "email": email,
            "mfa_enabled": mfa_enabled,
            "mfa_secret": secrets.token_urlsafe(32) if mfa_enabled else None,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None,
            "active": True
        }
        
        self._save_config()
        return True

    def authenticate_user(self, username: str, password: str, mfa_token: Optional[str] = None) -> Optional[str]:
        """
        Authenticate a user with password and optional MFA.
        
        Args:
            username: Username to authenticate
            password: Password for authentication
            mfa_token: Optional MFA token
            
        Returns:
            Session token if successful, None otherwise
        """
        if username not in self.users:
            return None
            
        user = self.users[username]
        if not user["active"]:
            return None
            
        # Verify password
        salt = base64.b64decode(user["salt"])
        password_hash = self._hash_password(password, salt)
        expected_hash = base64.b64decode(user["password_hash"])
        
        if not secrets.compare_digest(password_hash, expected_hash):
            return None
            
        # Check MFA if enabled
        if user["mfa_enabled"] and self.mfa_enabled:
            if not mfa_token or not self._verify_mfa_token(username, mfa_token):
                return None
                
        # Create session
        session_token = self._create_session(username)
        
        # Update last login
        self.users[username]["last_login"] = datetime.utcnow().isoformat()
        self._save_config()
        
        return session_token

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash a password with salt using PBKDF2."""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    def _create_session(self, username: str) -> str:
        """Create a new session for a user."""
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            "username": username,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        return session_token

    def _verify_mfa_token(self, username: str, token: str) -> bool:
        """
        Verify MFA token (simplified implementation).
        
        Args:
            username: Username to verify
            token: MFA token to verify
            
        Returns:
            True if valid, False otherwise
        """
        # This is a simplified implementation
        # In a real system, you would verify against TOTP, email code, etc.
        user = self.users[username]
        if not user["mfa_secret"]:
            return False
            
        # For demo purposes, we'll accept any 6-digit token
        # In a real implementation, this would verify against the actual MFA method
        return len(token) == 6 and token.isdigit()

    def validate_session(self, session_token: str) -> Optional[str]:
        """
        Validate a session token.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            Username if valid, None otherwise
        """
        if session_token not in self.sessions:
            return None
            
        session = self.sessions[session_token]
        
        # Check if session has expired
        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.utcnow() > expires_at:
            del self.sessions[session_token]
            return None
            
        return session["username"]

    def invalidate_session(self, session_token: str) -> bool:
        """
        Invalidate a session token.
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if successful, False otherwise
        """
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True
        return False

    def create_role(self, role_name: str, permissions: List[str]) -> bool:
        """
        Create a new role with specified permissions.
        
        Args:
            role_name: Name of the role
            permissions: List of permissions for the role
            
        Returns:
            True if successful, False otherwise
        """
        if role_name in self.roles:
            return False
            
        self.roles[role_name] = {
            "permissions": permissions,
            "created_at": datetime.utcnow().isoformat()
        }
        
        self._save_config()
        return True

    def assign_role_to_user(self, username: str, role_name: str) -> bool:
        """
        Assign a role to a user.
        
        Args:
            username: Username to assign role to
            role_name: Name of the role to assign
            
        Returns:
            True if successful, False otherwise
        """
        if username not in self.users or role_name not in self.roles:
            return False
            
        if role_name not in self.users[username]["roles"]:
            self.users[username]["roles"].append(role_name)
            self._save_config()
            
        return True

    def check_permission(self, username: str, permission: str) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            username: Username to check
            permission: Permission to check for
            
        Returns:
            True if user has permission, False otherwise
        """
        if username not in self.users:
            return False
            
        user = self.users[username]
        if not user["active"]:
            return False
            
        # Check direct permissions
        for role_name in user["roles"]:
            if role_name in self.roles:
                role = self.roles[role_name]
                if permission in role["permissions"]:
                    return True
                    
        return False

    def get_user_roles(self, username: str) -> List[str]:
        """
        Get all roles assigned to a user.
        
        Args:
            username: Username to get roles for
            
        Returns:
            List of role names
        """
        if username not in self.users:
            return []
            
        return self.users[username]["roles"]

    def get_role_permissions(self, role_name: str) -> List[str]:
        """
        Get all permissions for a role.
        
        Args:
            role_name: Role name to get permissions for
            
        Returns:
            List of permissions
        """
        if role_name not in self.roles:
            return []
            
        return self.roles[role_name]["permissions"]

    def enable_mfa(self) -> None:
        """Enable MFA system-wide."""
        self.mfa_enabled = True
        self._save_config()

    def disable_mfa(self) -> None:
        """Disable MFA system-wide."""
        self.mfa_enabled = False
        self._save_config()

    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user information (excluding sensitive data).
        
        Args:
            username: Username to get info for
            
        Returns:
            User information dictionary or None if user doesn't exist
        """
        if username not in self.users:
            return None
            
        user = self.users[username].copy()
        # Remove sensitive information
        user.pop("password_hash", None)
        user.pop("salt", None)
        user.pop("mfa_secret", None)
        
        return user

    def list_users(self) -> List[str]:
        """List all usernames."""
        return list(self.users.keys())

    def list_roles(self) -> List[str]:
        """List all role names."""
        return list(self.roles.keys())

# Global access control manager instance
_access_control_manager: Optional[AccessControlManager] = None

def initialize_access_control(config_path: Optional[str] = None) -> AccessControlManager:
    """Initialize and return the global access control manager."""
    global _access_control_manager
    if _access_control_manager is None:
        _access_control_manager = AccessControlManager(config_path)
    return _access_control_manager

def get_access_control_manager() -> Optional[AccessControlManager]:
    """Get the global access control manager instance."""
    return _access_control_manager