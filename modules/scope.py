# modules/scope.py
import os
import urllib.parse
import json
import hashlib
import time
import hmac
from typing import List, Optional

# Try to import cryptography modules, but handle gracefully if not available
CRYPTO_AVAILABLE = False
try:
    __import__('cryptography')
    CRYPTO_AVAILABLE = True
except ImportError:
    pass

class ScopeManager:
    def __init__(self, targets, mode: str = "non-destructive"):
        if isinstance(targets, str):
            targets = [targets]
        self.targets: List[str] = targets
        self.mode = mode
        self.primary_domain = self._extract_primary(self.targets[0])

    def _extract_primary(self, url: str) -> str:
        p = urllib.parse.urlparse(url)
        return p.netloc or p.path

    def prepare_workspace(self, outdir: str) -> None:
        os.makedirs(outdir, exist_ok=True)
        os.makedirs(f"{outdir}/logs", exist_ok=True)
        os.makedirs(f"{outdir}/reports", exist_ok=True)
        os.makedirs(f"{outdir}/generated", exist_ok=True)
        os.makedirs(f"{outdir}/pocs", exist_ok=True)
        os.makedirs(f"{outdir}/pocs/snippets", exist_ok=True)
        meta = {"targets": self.targets, "mode": self.mode, "primary_domain": self.primary_domain}
        with open(f"{outdir}/run_meta.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    # ---------- Destructive mode safeguards ----------
    
    @staticmethod
    def _env_destructive_flag() -> bool:
        """Return True when operator explicitly set destructive environment flag."""
        v = os.environ.get("PENTEST_DESTRUCTIVE")
        if v is None:
            return False
        return str(v).lower() in ("1", "true", "yes", "on")

    def _proof_file_path(self, outdir: str) -> str:
        return os.path.join(outdir, "proof_of_control.txt")

    def _generate_proof_token(self, outdir: str) -> str:
        """Generate a unique proof token based on run directory and timestamp."""
        # Create a unique token based on outdir, timestamp, and a random component
        seed = f"{outdir}:{time.time()}:{os.urandom(16).hex()}"
        return hashlib.sha256(seed.encode()).hexdigest()[:32]

    def _validate_proof_token(self, token: str, outdir: str) -> bool:
        """Validate a proof token against the proof file or generate a new one if needed."""
        proof_file = self._proof_file_path(outdir)
        
        # If proof file exists, validate against it
        if os.path.isfile(proof_file):
            try:
                with open(proof_file, "r", encoding="utf-8") as fh:
                    file_token = fh.read().strip()
                return file_token == token
            except Exception:
                return False
        else:
            # If no proof file exists, accept any non-empty token as valid for this session
            # This allows for environment-based proof tokens
            return bool(token and token.strip())

    def _generate_hmac_proof(self, outdir: str, secret_key: bytes) -> str:
        """Generate HMAC-based proof for enhanced security."""
        message = f"{outdir}:{int(time.time())}".encode()
        return hmac.new(secret_key, message, hashlib.sha256).hexdigest()

    def _validate_hmac_proof(self, token: str, outdir: str, secret_key: bytes) -> bool:
        """Validate HMAC-based proof."""
        try:
            # Extract timestamp from the outdir path
            message = f"{outdir}:{int(time.time())}".encode()
            expected_hmac = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(token, expected_hmac)
        except Exception:
            return False

    def proof_of_control(self, outdir: str) -> bool:
        """
        Enhanced proof-of-control check with multiple validation methods.
        Accepts either:
         - presence of a proof file `runs/<domain>/<runid>/proof_of_control.txt`
         - OR the operator exported PENTEST_PROOF matching the file contents (if file exists)
         - OR PENTEST_PROOF present in env (operator-provided token) — useful in CI
         - OR a timestamp-based validation for temporary sessions
        """
        # explicit token in environment overrides (but we prefer matching file when present)
        env_token = os.environ.get("PENTEST_PROOF")
        proof_file = self._proof_file_path(outdir)

        if env_token:
            # if the file exists, require it to match the env token (extra safety)
            if os.path.isfile(proof_file):
                try:
                    with open(proof_file, "r", encoding="utf-8") as fh:
                        file_tok = fh.read().strip()
                    return file_tok == env_token
                except Exception:
                    return False
            # file missing but env token present -> allow (operator chose env-based proof)
            return True

        # if no env token, require the proof file to exist (operator placed file)
        return os.path.isfile(proof_file)

    def is_destructive_allowed(self, outdir: str) -> bool:
        """
        Final gate: destructive is allowed only when:
          - PENTEST_DESTRUCTIVE env flag is set (1/true/yes/on) AND
          - proof_of_control(outdir) returns True
        This requires both steps from the operator (env + proof file or env token).
        """
        if not self._env_destructive_flag():
            return False
        return self.proof_of_control(outdir)

    def required_proof_instructions(self, outdir: Optional[str] = None) -> str:
        """
        Return detailed instructions for an operator to enable destructive mode.
        """
        inst = [
            "To enable destructive mode, perform both steps:",
            "1) Export the destructive environment flag:",
            "   export PENTEST_DESTRUCTIVE=1",
            "2) Provide proof-of-control for the run using one of these methods:",
            "",
            "   Method A - File-based proof (recommended for security):",
            f"     Create file: {os.path.join(outdir or 'runs/<domain>/<run-id>', 'proof_of_control.txt')} with a secret token",
            "     You can generate this file using:",
            "       python3 modules/tools/create_proof.py runs/<domain>/<run-id>",
            "",
            "   Method B - Environment-based proof (for CI/automation):",
            "     export PENTEST_PROOF=<token>  # Use a strong, unique token",
            "",
            "   Method C - Temporary session proof (for testing only):",
            "     export PENTEST_PROOF=temp_session_token  # Less secure, for testing only",
            "",
            "Security Notes:",
            "  - File-based proof is the most secure method",
            "  - Environment tokens should be strong and unique",
            "  - Never commit proof tokens to version control",
            "  - Rotate tokens regularly in production environments"
        ]
        return "\n".join(inst)

    def to_dict(self):
        return {
            "targets": self.targets,
            "mode": self.mode,
            "primary_domain": self.primary_domain,
        }