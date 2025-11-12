#!/usr/bin/env python3
"""
Demo script showcasing the new enterprise-grade performance and scalability features.
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def demo_distributed_scanning():
    """Demonstrate distributed scanning capabilities."""
    print("🌐 Demonstrating Distributed Scanning Capabilities")
    print("=" * 50)
    
    from modules.distributed_scanner import DistributedScanner, DistributedScanCoordinator
    
    # Show distributed scanner features
    print("Distributed Scanner Features:")
    print("  • Multi-node orchestration using Redis task queues")
    print("  • Horizontal scaling across worker nodes")
    print("  • Fault-tolerant scan coordination")
    print("  • Real-time progress tracking")
    print("  • Scan cancellation capabilities")
    
    # Show coordinator features
    print("\nDistributed Coordinator Features:")
    print("  • Centralized scan management")
    print("  • Result aggregation from multiple nodes")
    print("  • Cluster status monitoring")
    print("  • Load balancing across nodes")
    
    print("\n✅ Distributed Scanning demonstration completed\n")

def demo_resource_monitoring():
    """Demonstrate resource monitoring features."""
    print("📊 Demonstrating Resource Monitoring Features")
    print("=" * 45)
    
    from modules.resource_monitor import ResourceMonitor, AdaptiveResourceOptimizer
    
    # Show resource monitor features
    print("Resource Monitor Features:")
    print("  • Real-time CPU, memory, and disk usage tracking")
    print("  • Network I/O monitoring")
    print("  • Process-level resource consumption")
    print("  • Historical metrics storage")
    print("  • Customizable alert thresholds")
    
    # Show optimizer features
    print("\nAdaptive Resource Optimizer Features:")
    print("  • Automatic scan parameter adjustment")
    print("  • Dynamic parallelization control")
    print("  • Memory cache optimization")
    print("  • I/O throttling based on system load")
    print("  • Performance bottleneck detection")
    
    print("\n✅ Resource Monitoring demonstration completed\n")

def demo_intelligent_caching():
    """Demonstrate intelligent caching features."""
    print("キャッシング Demonstrating Intelligent Caching Features")
    print("=" * 45)
    
    from modules.cache_manager import IntelligentCache
    
    # Show cache features
    print("Intelligent Cache Features:")
    print("  • Scan result caching with TTL expiration")
    print("  • LRU (Least Recently Used) eviction policy")
    print("  • Configurable size limits")
    print("  • Cache hit/miss tracking")
    print("  • Target and scan-type based caching")
    print("  • Cache invalidation controls")
    
    # Show cache statistics
    cache = IntelligentCache()
    stats = cache.get_stats()
    print(f"\nCache Statistics:")
    print(f"  • Total Entries: {stats.get('total_entries', 0)}")
    print(f"  • Total Size: {stats.get('total_size_mb', 0)} MB")
    print(f"  • Max Size: {stats.get('max_size_mb', 0)} MB")
    
    print("\n✅ Intelligent Caching demonstration completed\n")

def demo_multi_tenancy():
    """Demonstrate multi-tenant support features."""
    print("🏢 Demonstrating Multi-Tenant Support Features")
    print("=" * 45)
    
    from modules.tenant_manager import TenantManager
    
    # Create tenant manager
    tenant_manager = TenantManager()
    
    # Show tenant features
    print("Multi-Tenant Features:")
    print("  • Isolated scanning environments")
    print("  • Target access control policies")
    print("  • Scan limit enforcement")
    print("  • Tenant-specific configurations")
    print("  • Resource quota management")
    print("  • Audit logging per tenant")
    
    # Create demo tenants
    print("\nCreating Demo Tenants:")
    
    # Security team tenant
    sec_team_id = tenant_manager.create_tenant(
        name="Security Team",
        config={"scan_profile": "thorough", "notifications": True},
        allowed_targets=["*.company.com", "*.internal.company.com"],
        scan_limit=100
    )
    print(f"  • Security Team (ID: {sec_team_id[:8]}...)")
    
    # Development team tenant
    dev_team_id = tenant_manager.create_tenant(
        name="Development Team",
        config={"scan_profile": "quick", "notifications": False},
        allowed_targets=["dev.*.company.com", "staging.*.company.com"],
        scan_limit=25
    )
    print(f"  • Development Team (ID: {dev_team_id[:8]}...)")
    
    # Show tenant validation
    sec_allowed = tenant_manager.is_target_allowed(sec_team_id, "api.company.com")
    dev_allowed = tenant_manager.is_target_allowed(dev_team_id, "api.company.com")
    print(f"\nTarget Access Control:")
    print(f"  • api.company.com allowed for Security Team: {sec_allowed}")
    print(f"  • api.company.com allowed for Development Team: {dev_allowed}")
    
    # Clean up demo tenants
    tenant_manager.delete_tenant(sec_team_id)
    tenant_manager.delete_tenant(dev_team_id)
    
    print("\n✅ Multi-Tenant Support demonstration completed\n")

def demo_cloud_deployment():
    """Demonstrate cloud deployment options."""
    print("☁️  Demonstrating Cloud Deployment Options")
    print("=" * 40)
    
    print("Containerization Features:")
    print("  • Docker images for easy deployment")
    print("  • Multi-container architecture")
    print("  • Persistent volume support")
    print("  • Environment variable configuration")
    
    print("\nKubernetes Features:")
    print("  • Helm chart support (coming soon)")
    print("  • Horizontal pod autoscaling")
    print("  • Persistent volume claims")
    print("  • Service discovery and load balancing")
    print("  • Secret management")
    print("  • Resource quotas and limits")
    
    print("\nCloud Provider Integration:")
    print("  • AWS deployment templates")
    print("  • Azure Resource Manager templates")
    print("  • Google Cloud Deployment Manager")
    print("  • Multi-cloud deployment strategies")
    
    print("\n✅ Cloud Deployment demonstration completed\n")

def main():
    """Run all demonstrations."""
    print("PenAI Enterprise-Grade Features Demo")
    print("=" * 35)
    print("This demo showcases the new enterprise-grade performance and")
    print("scalability capabilities added to the framework.\n")
    
    demo_distributed_scanning()
    demo_resource_monitoring()
    demo_intelligent_caching()
    demo_multi_tenancy()
    demo_cloud_deployment()
    
    print("🎉 Demo completed!")
    print("\nTo use these enterprise features in practice:")
    print("1. Deploy Redis for distributed scanning coordination")
    print("2. Use --distributed flag for large-scale scans")
    print("3. Enable --monitor-resources for performance tracking")
    print("4. Use --enable-caching to reduce redundant operations")
    print("5. Configure tenants with --tenant-id for multi-tenant environments")
    print("6. Deploy with Docker or Kubernetes for cloud-native scalability")

if __name__ == "__main__":
    main()