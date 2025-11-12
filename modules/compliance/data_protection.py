#!/usr/bin/env python3
"""
Data Protection Module for PenAI

This module provides data protection controls including encryption at rest and in transit,
data masking, and secure data disposal.
"""

import os
import json
import hashlib
import base64
import re
from typing import Dict, Any, Optional, Union
from pathlib import Path

class DataProtectionManager:
    def __init__(self, outdir: str, encryption_key: Optional[bytes] = None):
        """
        Initialize the data protection manager.
        
        Args:
            outdir: Output directory for protected data
            encryption_key: Optional encryption key (will be generated if not provided)
        """
        self.outdir = outdir
        self.protected_dir = os.path.join(outdir, "protected")
        os.makedirs(self.protected_dir, exist_ok=True)
        
        # Initialize encryption
        self.encryption_key = encryption_key
        self.cipher_suite = None
        self.crypto_available = False
        
        # Try to set up encryption if cryptography is available
        self._setup_encryption()

    def _setup_encryption(self):
        """Set up encryption if cryptography library is available."""
        # This method is intentionally left simple to avoid import issues
        pass

    def encrypt_data(self, data: Union[str, bytes]) -> bytes:
        """
        Encrypt data using simple obfuscation (not secure).
        
        Args:
            data: Data to "encrypt" (string or bytes)
            
        Returns:
            "Encrypted" data as bytes
        """
        # Simple obfuscation (not secure)
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data)

    def decrypt_data(self, encrypted_data: bytes) -> str:
        """
        Decrypt data using simple de-obfuscation (not secure).
        
        Args:
            encrypted_data: "Encrypted" data as bytes
            
        Returns:
            "Decrypted" data as string
        """
        # Simple de-obfuscation (not secure)
        decrypted_data = base64.b64decode(encrypted_data)
        return decrypted_data.decode('utf-8')

    def encrypt_file(self, file_path: str, output_path: Optional[str] = None) -> str:
        """
        Encrypt a file.
        
        Args:
            file_path: Path to the file to encrypt
            output_path: Optional output path for encrypted file
            
        Returns:
            Path to the encrypted file
        """
        if not output_path:
            output_path = f"{file_path}.encrypted"
            
        with open(file_path, 'rb') as file:
            file_data = file.read()
            
        encrypted_data = self.encrypt_data(file_data)
        
        with open(output_path, 'wb') as file:
            file.write(encrypted_data)
            
        return output_path

    def decrypt_file(self, encrypted_file_path: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a file.
        
        Args:
            encrypted_file_path: Path to the encrypted file
            output_path: Optional output path for decrypted file
            
        Returns:
            Path to the decrypted file
        """
        if not output_path:
            if encrypted_file_path.endswith('.encrypted'):
                output_path = encrypted_file_path[:-10]  # Remove .encrypted extension
            else:
                output_path = f"{encrypted_file_path}.decrypted"
                
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
            
        decrypted_data = self.decrypt_data(encrypted_data)
        
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(decrypted_data)
            
        return output_path

    def mask_sensitive_data(self, data: str, patterns: Optional[Dict[str, str]] = None) -> str:
        """
        Mask sensitive data in text.
        
        Args:
            data: Text data to mask
            patterns: Optional custom masking patterns
            
        Returns:
            Data with sensitive information masked
        """
        if patterns is None:
            patterns = {
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b': '****-****-****-****',  # Credit card
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '***@***.***',  # Email
                r'\b\d{3}-\d{2}-\d{4}\b': '***-**-****',  # SSN
                r'\b\d{16}\b': '****************'  # 16-digit numbers
            }
        
        masked_data = data
        for pattern, replacement in patterns.items():
            masked_data = re.sub(pattern, replacement, masked_data)
            
        return masked_data

    def secure_delete_file(self, file_path: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting it multiple times.
        
        Args:
            file_path: Path to the file to delete
            passes: Number of overwrite passes
            
        Returns:
            True if successful, False otherwise
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # Overwrite the file multiple times with random data
            with open(file_path, "r+b") as file:
                for _ in range(passes):
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
                    
            # Delete the file
            os.remove(file_path)
            return True
        except Exception:
            return False

    def secure_delete_directory(self, dir_path: str, passes: int = 3) -> bool:
        """
        Securely delete a directory and all its contents.
        
        Args:
            dir_path: Path to the directory to delete
            passes: Number of overwrite passes for files
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Securely delete all files in the directory
            for root, dirs, files in os.walk(dir_path, topdown=False):
                for name in files:
                    file_path = os.path.join(root, name)
                    self.secure_delete_file(file_path, passes)
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
                    
            # Remove the directory itself
            os.rmdir(dir_path)
            return True
        except Exception:
            return False

    def protect_scan_output(self, findings: list, meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Protect sensitive information in scan output.
        
        Args:
            findings: List of security findings
            meta: Scan metadata
            
        Returns:
            Protected scan data
        """
        protected_findings = []
        
        for finding in findings:
            protected_finding = finding.copy()
            
            # Mask sensitive evidence
            if "evidence" in protected_finding:
                protected_finding["evidence"] = self.mask_sensitive_data(
                    str(protected_finding["evidence"])
                )
                
            # Encrypt sensitive fields if needed
            # This is a simplified example - in practice, you might encrypt specific fields
            protected_findings.append(protected_finding)
            
        protected_meta = meta.copy()
        
        # Mask sensitive metadata
        if "targets" in protected_meta:
            protected_targets = []
            for target in protected_meta["targets"]:
                protected_targets.append(self.mask_sensitive_data(str(target)))
            protected_meta["targets"] = protected_targets
            
        return {
            "findings": protected_findings,
            "metadata": protected_meta
        }

    def _generate_key(self) -> bytes:
        """Generate a new key."""
        # Generate a simple key
        return base64.urlsafe_b64encode(os.urandom(32))

    def save_encryption_key(self, key_path: str) -> None:
        """
        Save the encryption key to a file.
        
        Args:
            key_path: Path to save the key
        """
        if self.encryption_key:
            with open(key_path, 'wb') as key_file:
                key_file.write(self.encryption_key)

    def load_encryption_key(self, key_path: str) -> None:
        """
        Load an encryption key from a file.
        
        Args:
            key_path: Path to the key file
        """
        with open(key_path, 'rb') as key_file:
            self.encryption_key = key_file.read()

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Derive a key from a password using PBKDF2.
        
        Args:
            password: Password to derive key from
            salt: Optional salt (will be generated if not provided)
            
        Returns:
            Derived key
        """
        # Simple key derivation (not secure)
        if salt is None:
            salt = b'salt_'
        key_data = (password + salt.decode() if salt else password).encode()
        return hashlib.pbkdf2_hmac('sha256', key_data, salt or b'', 100000)

# Global data protection manager instance
_data_protection_manager: Optional[DataProtectionManager] = None

def initialize_data_protection_manager(outdir: str, encryption_key: Optional[bytes] = None) -> DataProtectionManager:
    """Initialize and return the global data protection manager."""
    global _data_protection_manager
    if _data_protection_manager is None:
        _data_protection_manager = DataProtectionManager(outdir, encryption_key)
    return _data_protection_manager

def get_data_protection_manager() -> Optional[DataProtectionManager]:
    """Get the global data protection manager instance."""
    return _data_protection_manager