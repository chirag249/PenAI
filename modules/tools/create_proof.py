#!/usr/bin/env python3
"""
create_proof.py

Create a proof_of_control.txt in a run directory to satisfy destructive safeguards.

Usage:
  python3 create_proof.py runs/<domain>/<run-id> [--token <token>] [--print-only]

If --token is omitted, a UUID4 token will be generated and written.
The script sets file permissions to 600 when possible.
It prints exact export instructions for the operator.
"""
from __future__ import annotations
import argparse
import os
import sys
import uuid
import hashlib
import time
from pathlib import Path
from typing import Optional

def generate_secure_token(run_dir: str) -> str:
    """Generate a cryptographically secure token for the run."""
    # Create a unique token based on run directory, timestamp, and system randomness
    seed = f"{run_dir}:{time.time()}:{os.urandom(32).hex()}"
    return hashlib.sha256(seed.encode()).hexdigest()

def write_proof(run_dir: Path, token: str) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    proof_path = run_dir / "proof_of_control.txt"
    # write token
    with proof_path.open("w", encoding="utf-8") as fh:
        fh.write(str(token).strip() + "\n")
    try:
        proof_path.chmod(0o600)
    except Exception:
        # ignore chmod failures on non-POSIX
        pass
    return proof_path

def validate_existing_proof(run_dir: Path) -> Optional[str]:
    """Validate if an existing proof file is present and return its token."""
    proof_path = run_dir / "proof_of_control.txt"
    if proof_path.exists():
        try:
            with proof_path.open("r", encoding="utf-8") as fh:
                return fh.read().strip()
        except Exception:
            return None
    return None

def main():
    p = argparse.ArgumentParser(description="Create proof-of-control token for destructive testing")
    p.add_argument("run_dir", help="runs/<domain>/<run-id>")
    p.add_argument("--token", help="Explicit token to write (optional)")
    p.add_argument("--print-only", action="store_true", help="Don't write file; only print instructions and a token")
    p.add_argument("--validate", action="store_true", help="Validate existing proof file")
    args = p.parse_args()

    run_dir = Path(args.run_dir)
    
    # Validation mode
    if args.validate:
        existing_token = validate_existing_proof(run_dir)
        if existing_token:
            print("✓ Valid proof of control file found")
            print(f"Token: {existing_token}")
            return 0
        else:
            print("✗ No valid proof of control file found")
            return 1

    # Generate or use provided token
    if args.token:
        token = args.token
    else:
        token = generate_secure_token(str(run_dir))

    print("=" * 60)
    print("DESTRUCTIVE MODE PROOF CREATION")
    print("=" * 60)
    print("Run dir:", str(run_dir))
    print("Token:", token)
    print()

    if args.print_only:
        print("Dry-run (did not write file).")
    else:
        proof_path = write_proof(run_dir, token)
        print(f"✓ Wrote proof file: {proof_path}")
        print()

    print("SECURITY INSTRUCTIONS:")
    print("=" * 60)
    print("To enable destructive runs for this run, on the operator machine do:")
    print()
    print("  export PENTEST_DESTRUCTIVE=1")
    print(f"  export PENTEST_PROOF={token}")
    print()
    print("ALTERNATIVE METHODS:")
    print("1. File-based validation (already created above):")
    print(f"   The file {run_dir / 'proof_of_control.txt'} contains your token")
    print()
    print("2. For CI/CD environments:")
    print("   export PENTEST_DESTRUCTIVE=1")
    print("   export PENTEST_PROOF=your_ci_token_here")
    print()
    print("3. For temporary testing (less secure):")
    print("   export PENTEST_DESTRUCTIVE=1")
    print("   export PENTEST_PROOF=temp_test_token")
    print()
    print("RUNNING THE AGENT:")
    print("After setting the environment variables, run:")
    print("  python3 agent.py --targets <target> --run-id <id>")
    print()
    print("SECURITY BEST PRACTICES:")
    print("- Keep proof tokens secret and never commit them to version control")
    print("- Rotate tokens regularly in production environments")
    print("- Use file-based proofs for maximum security")
    print("- Validate proofs before running destructive tests")
    print("=" * 60)

    # Show validation command
    print()
    print("To validate this proof later, run:")
    print(f"  python3 modules/tools/create_proof.py {args.run_dir} --validate")

if __name__ == "__main__":
    main()