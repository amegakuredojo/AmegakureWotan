import os
import json
import logging
import gnupg
import hashlib
from pathlib import Path
from typing import Dict, Optional
from amegakurewotan.config import get_config

logger = logging.getLogger("amegakurewotan.policy.vault")

class CredentialVault:
    """
    Symmetrically encrypts and stores sensitive service API keys (Shodan, Censys, Intelx)
    using local gnupg. Passphrase is cryptographically derived from the node's
    local machine-specific audit master key.
    """
    def __init__(self):
        config = get_config()
        self.vault_file = config.base_dir / "opsec" / "credentials.json.gpg"
        self.key_path = config.base_dir / "opsec" / "keys" / "audit_master.key"
        # Explicit home directory for GPG structures inside the workspace config path
        gpg_home = config.base_dir / "opsec" / "gnupg"
        gpg_home.mkdir(parents=True, exist_ok=True)
        try:
            # Set strict permissions on gpg keyring directory (0700)
            os.chmod(gpg_home, 0o700)
        except Exception:
            pass
        self.gpg = gnupg.GPG(gnupghome=str(gpg_home))

    def _get_master_passphrase(self) -> str:
        """Retrieves or initializes the master passphrase from the audit master key."""
        if not self.key_path.exists():
            # If the audit key does not exist, initialize it
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            secret = os.urandom(64)
            with open(os.open(self.key_path, os.O_CREAT | os.O_WRONLY, 0o600), "wb") as f:
                f.write(secret)
            logger.info("CredentialVault: Forensic master audit key initialized.")
            
        with open(self.key_path, "rb") as f:
            return hashlib.sha512(f.read()).hexdigest()

    def get_credential(self, service: str) -> Optional[str]:
        """Retrieves a single credential for a service (e.g. 'shodan', 'censys')."""
        creds = self.list_credentials()
        return creds.get(service.lower())

    def set_credential(self, service: str, api_key: str) -> None:
        """Stores a credential for a service securely."""
        if not service or not service.strip():
            raise ValueError("Service name cannot be empty.")
        if not api_key or not api_key.strip():
            raise ValueError("API key value cannot be empty.")
            
        creds = self.list_credentials()
        creds[service.lower()] = api_key
        
        # Symmetrically encrypt the json string
        passphrase = self._get_master_passphrase()
        raw_json = json.dumps(creds)
        
        status = self.gpg.encrypt(
            raw_json,
            recipients=None, # None triggers symmetric cipher mode
            symmetric=True,
            passphrase=passphrase,
            output=str(self.vault_file)
        )
        
        if not status.ok:
            raise RuntimeError(f"Failed to encrypt credentials vault: {status.stderr}")
            
        # Set strict permissions on the encrypted vault file (0600)
        if self.vault_file.exists():
            try:
                os.chmod(self.vault_file, 0o600)
            except Exception:
                pass
        logger.info(f"Credential for service '{service}' saved securely.")

    def delete_credential(self, service: str) -> None:
        """Deletes a stored credential."""
        creds = self.list_credentials()
        service_clean = service.lower()
        if service_clean in creds:
            del creds[service_clean]
            
            passphrase = self._get_master_passphrase()
            raw_json = json.dumps(creds)
            
            status = self.gpg.encrypt(
                raw_json,
                recipients=None,
                symmetric=True,
                passphrase=passphrase,
                output=str(self.vault_file)
            )
            if not status.ok:
                raise RuntimeError(f"Failed to save credentials vault after deletion: {status.stderr}")
            logger.info(f"Credential for service '{service}' deleted.")

    def list_credentials(self) -> Dict[str, str]:
        """Decrypts and lists all credentials in the vault."""
        if not self.vault_file.exists() or self.vault_file.stat().st_size == 0:
            return {}
            
        passphrase = self._get_master_passphrase()
        try:
            with open(self.vault_file, "rb") as f:
                status = self.gpg.decrypt_file(f, passphrase=passphrase)
                
            if not status.ok:
                logger.error(f"Failed to decrypt credentials vault: {status.stderr}")
                return {}
                
            return json.loads(status.data.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to parse credentials vault: {e}")
            return {}
