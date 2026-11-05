"""
Encryption of stored credentials (Fernet: AES-128-CBC + HMAC-SHA256).

Keys come from, in order of precedence:

1. ``PLUGINS_CONFIG["netbox_nmap_discovery"]["encryption_key"]`` - a string or a list of strings;
2. the ``NETBOX_DISCOVERY_ENCRYPTION_KEY`` environment variable (comma-separated for several keys);
3. a key derived from Django's ``SECRET_KEY`` (a warning is logged; rotating SECRET_KEY then makes stored
   credentials unreadable).

The first key encrypts; every key is tried for decryption, which allows key rotation with
``manage.py discovery_rotate_key``. Values that are not valid Fernet keys are stretched with HKDF-SHA256.
"""
from __future__ import annotations

import base64
import logging
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ("CredentialDecryptionError", "decrypt", "encrypt", "get_fernet", "rotate")

logger = logging.getLogger("netbox_nmap_discovery.crypto")

ENV_VAR = "NETBOX_DISCOVERY_ENCRYPTION_KEY"
_HKDF_SALT = b"netbox-nmap-discovery"
_HKDF_INFO = b"credential-encryption-v1"


_warned_fallback = False


class CredentialDecryptionError(Exception):
    pass


def _to_fernet_key(value: str) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    try:
        if len(base64.urlsafe_b64decode(raw)) == 32:
            return raw
    except (ValueError, TypeError):
        pass
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=_HKDF_INFO).derive(raw)
    return base64.urlsafe_b64encode(derived)


def _configured_keys() -> list[str]:
    from django.conf import settings

    configured = None
    try:
        from netbox.plugins import get_plugin_config

        configured = get_plugin_config("netbox_nmap_discovery", "encryption_key")
    except Exception:  # pragma: no cover - plugin not loaded (management shell, tests)
        configured = (getattr(settings, "PLUGINS_CONFIG", {}).get("netbox_nmap_discovery") or {}).get("encryption_key")
    if configured:
        return [configured] if isinstance(configured, str) else [k for k in configured if k]
    env = os.environ.get(ENV_VAR)
    if env:
        return [k.strip() for k in env.split(",") if k.strip()]
    global _warned_fallback
    if not _warned_fallback:
        _warned_fallback = True
        logger.warning(
            "No encryption_key configured for netbox_nmap_discovery; deriving one from SECRET_KEY. Set "
            "PLUGINS_CONFIG['netbox_nmap_discovery']['encryption_key'] or %s so credentials survive SECRET_KEY "
            "rotation.", ENV_VAR,
        )
    return [settings.SECRET_KEY]


def get_fernet() -> MultiFernet:
    return MultiFernet([Fernet(_to_fernet_key(k)) for k in _configured_keys()])


def encrypt(plaintext: str | None) -> str:
    if not plaintext:
        return ""
    return get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str | None) -> str:
    if not token:
        return ""
    try:
        return get_fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise CredentialDecryptionError(
            "Unable to decrypt stored credential: the encryption key has changed. Re-enter the credential or "
            "restore the previous key."
        ) from exc


def rotate(token: str | None) -> str:
    """Re-encrypt ``token`` with the current (first) key."""
    if not token:
        return ""
    return get_fernet().rotate(token.encode()).decode()
