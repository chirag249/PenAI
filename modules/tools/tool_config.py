#!/usr/bin/env python3
"""
Tool configuration system for sophisticated parameter tuning.

This module provides a flexible configuration system that allows for:
- Per-tool parameter customization
- Profile-based configurations (e.g., quick, thorough, stealth)
- Target-specific overrides
- Environment-based settings
"""

from __future__ import annotations
import os
import json
from typing import Dict, Any, List, Optional, Union
from pathlib import Path

# Default tool configurations
DEFAULT_TOOL_CONFIGS = {
    "nmap": {
        "profiles": {
            "quick": {
                "args": ["-Pn", "-sS", "--top-ports", "100"],
                "timeout": 60
            },
            "normal": {
                "args": ["-Pn", "-sS", "-sV", "--top-ports", "1000"],
                "timeout": 120
            },
            "thorough": {
                "args": ["-Pn", "-sS", "-sV", "-O", "--script", "default,safe"],
                "timeout": 300
            },
            "stealth": {
                "args": ["-Pn", "-sS", "-f", "--scan-delay", "5", "--max-rate", "10"],
                "timeout": 600
            }
        },
        "default_profile": "normal"
    },
    "sqlmap": {
        "profiles": {
            "quick": {
                "args": ["--batch", "--risk=1", "--level=1", "--random-agent", "--timeout=10"],
                "timeout": 120
            },
            "normal": {
                "args": ["--batch", "--risk=2", "--level=2", "--random-agent", "--timeout=30"],
                "timeout": 240
            },
            "thorough": {
                "args": ["--batch", "--risk=3", "--level=3", "--random-agent", "--timeout=60", "--tamper=space2comment"],
                "timeout": 600
            }
        },
        "default_profile": "normal"
    },
    "nikto": {
        "profiles": {
            "quick": {
                "args": ["-Cgidirs", "none", "-maxtime", "300"],
                "timeout": 300
            },
            "normal": {
                "args": ["-Cgidirs", "none"],
                "timeout": 600
            },
            "thorough": {
                "args": [],
                "timeout": 1200
            }
        },
        "default_profile": "normal"
    },
    "wpscan": {
        "profiles": {
            "quick": {
                "args": ["--no-banner", "--disable-tls-checks", "--max-threads", "5"],
                "timeout": 120
            },
            "normal": {
                "args": ["--no-banner", "--disable-tls-checks", "--max-threads", "10"],
                "timeout": 300
            },
            "thorough": {
                "args": ["--no-banner", "--disable-tls-checks", "--max-threads", "20", "--enumerate", "vp,vt,cb,dbe"],
                "timeout": 600
            }
        },
        "default_profile": "normal"
    },
    "nuclei": {
        "profiles": {
            "quick": {
                "args": ["-silent", "-json", "-tags", "misconfig"],
                "timeout": 120
            },
            "normal": {
                "args": ["-silent", "-json", "-tags", "misconfig,vuln"],
                "timeout": 300
            },
            "thorough": {
                "args": ["-silent", "-json", "-tags", "misconfig,vuln,file"],
                "timeout": 600
            }
        },
        "default_profile": "normal"
    },
    "sslyze": {
        "profiles": {
            "quick": {
                "args": ["--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3", "--certinfo", "--compression", "--heartbleed"],
                "timeout": 120
            },
            "normal": {
                "args": ["--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3", "--certinfo", "--compression", "--heartbleed", "--openssl_ccs", "--reneg"],
                "timeout": 240
            },
            "thorough": {
                "args": ["--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3", "--certinfo", "--compression", "--heartbleed", "--openssl_ccs", "--reneg", "--resum", "--early_data"],
                "timeout": 480
            },
            "stealth": {
                "args": ["--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--certinfo", "--compression", "--timeout", "5"],
                "timeout": 180
            }
        },
        "default_profile": "normal"
    }
}

class ToolConfigManager:
    """Manages tool configurations with support for profiles and overrides."""
    
    def __init__(self, config_dir: Optional[str] = None):
        # Use environment variable if no config_dir specified
        if not config_dir:
            config_dir = os.environ.get("PENAI_CONFIG_DIR")
        
        self.config_dir = Path(config_dir) if config_dir else None
        self.tool_configs = DEFAULT_TOOL_CONFIGS.copy()
        self._load_custom_configs()
    
    def _load_custom_configs(self):
        """Load custom configurations from config directory if it exists."""
        if not self.config_dir or not self.config_dir.exists():
            return
            
        for config_file in self.config_dir.glob("*.json"):
            try:
                with open(config_file, "r") as f:
                    custom_config = json.load(f)
                tool_name = config_file.stem
                if tool_name in self.tool_configs:
                    # Merge with existing config
                    self.tool_configs[tool_name].update(custom_config)
                else:
                    self.tool_configs[tool_name] = custom_config
            except Exception:
                # Silently ignore invalid config files
                pass
    
    def get_tool_config(self, tool_name: str, profile: Optional[str] = None) -> Dict[str, Any]:
        """
        Get configuration for a specific tool and profile.
        
        Args:
            tool_name: Name of the tool
            profile: Profile name (quick, normal, thorough, etc.)
            
        Returns:
            Dictionary with 'args' and 'timeout' keys
        """
        if tool_name not in self.tool_configs:
            # Return default safe configuration
            return {"args": [], "timeout": 120}
            
        tool_config = self.tool_configs[tool_name]
        profiles = tool_config.get("profiles", {})
        
        # Determine profile to use
        if not profile:
            profile = os.environ.get(f"PENAI_{tool_name.upper()}_PROFILE") or \
                     os.environ.get("PENAI_DEFAULT_PROFILE") or \
                     tool_config.get("default_profile", "normal")
        
        # Get profile config
        if profile in profiles:
            return profiles[profile].copy()
        elif "normal" in profiles:
            return profiles["normal"].copy()
        else:
            # Return first available profile
            first_profile = next(iter(profiles.values())) if profiles else {}
            return first_profile.copy() if first_profile else {"args": [], "timeout": 120}
    
    def get_scan_profile(self) -> str:
        """Get the global scan profile from environment or default."""
        return os.environ.get("PENAI_SCAN_PROFILE", "normal")
    
    def get_tool_args(self, tool_name: str, profile: Optional[str] = None) -> List[str]:
        """Get command line arguments for a tool."""
        config = self.get_tool_config(tool_name, profile)
        return config.get("args", [])
    
    def get_tool_timeout(self, tool_name: str, profile: Optional[str] = None) -> int:
        """Get timeout for a tool."""
        config = self.get_tool_config(tool_name, profile)
        return config.get("timeout", 120)

# Global instance
tool_config_manager = ToolConfigManager()

def get_tool_config(tool_name: str, profile: Optional[str] = None) -> Dict[str, Any]:
    """Get configuration for a specific tool."""
    return tool_config_manager.get_tool_config(tool_name, profile)

def get_tool_args(tool_name: str, profile: Optional[str] = None) -> List[str]:
    """Get command line arguments for a tool."""
    return tool_config_manager.get_tool_args(tool_name, profile)

def get_tool_timeout(tool_name: str, profile: Optional[str] = None) -> int:
    """Get timeout for a tool."""
    return tool_config_manager.get_tool_timeout(tool_name, profile)

def get_scan_profile() -> str:
    """Get the global scan profile."""
    return tool_config_manager.get_scan_profile()