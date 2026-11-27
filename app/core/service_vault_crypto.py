"""Service vault context cryptography per ADR-0010 §§3/5/13 as amended by §17 (IMPL-014).

The service vault context holds the cryptographic material a service account
needs to unlock the shared vault server-side, encrypted with the environment
provisioned ``SERVICE_VAULT_KEY`` — never with the master password, and never
stored in the database as a column (ADR-0010 §3, ADR-0017).

Key properties:
- AEAD (AES-256-GCM): tampering with the ciphertext is detected on decrypt.
- Domain separation: the data key is HKDF-SHA256(service_vault_key, salt=
  service_id), so the same key material produces different ciphertext per
  service and a sealed blob cannot be swapped between services.
- Only a *key identifier* (``SERVICE_VAULT_KEY_INFO``) is persisted next to
  the blob, never the key material itself.
- Per-service DEKs (Data Encryption Keys) wrapped by the master key,
  supporting independent rotation (IMPL-014).
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.service_vault_keyring import (
    ServiceVaultDecryptError,
    ServiceVaultKeyMissing,
    ServiceVaultKeyUnreadable,
    current_master_key,
    get_service_dek,
    master_key_for_id,
    provision_service_dek,
    rewrap_all_service_deks,
    rewrap_service_deks,
)

#: Identifier stored in ``encrypted_with_key`` — names the key, is not it.
SERVICE_VAULT_KEY_INFO = b"service_vault_key_v1"
SERVICE_VAULT_CONTEXT_VERSION = 1
SERVICE_VAULT_KEY_ENV = "SERVICE_VAULT_KEY"
_KEY_LENGTH = 32  # AES-256
_IV_LENGTH = 12  # AES-GCM standard nonce

#: Process-local registry of single-shot seal nonces awaiting their one read.
_ONE_SHOT_SEALS: set[bytes] = set()
#: Nonces whose one read has completed. A consumed seal stays dead even when
#: the same blob is re-presented through the codec fallback order.
_ONE_SHOT_CONSUMED: set[bytes] = set()


class ServiceVaultKeyError(RuntimeError):
    """SERVICE_VAULT_KEY is missing or malformed (fail-secure)."""

# Re-export ServiceVaultDecryptError for backward compatibility
ServiceVaultContextDecryptError = ServiceVaultDecryptError


def _normalize_key_material(raw: Any) -> bytes:
    """Coerce configured key material to bytes (str utf-8, base64/hex 32B, bytes)."""
    if isinstance(raw, bytes):
        return raw[:_KEY_LENGTH] if len(raw) > _KEY_LENGTH else raw
    text = str(raw).strip()
    try:
        decoded = base64.b64decode(text, validate=True)
    except Exception:
        decoded = b""
    if decoded and len(decoded) == _KEY_LENGTH and len(text) == 44:
        return decoded
    encoded = text.encode("utf-8")
    return encoded[:_KEY_LENGTH] if len(encoded) > _KEY_LENGTH else encoded


def seal_scope(service_id: Any) -> Any:
    """Canonical seal domain for a service vault context."""
    return f"svc|{service_id}" if service_id else ""


MAGIC_ENVELOPE = b"SVB1"  # versioned envelope: length-prefixed service id + AEAD blob
_MAGIC_LEGACY_B64 = None  # early dev blobs (base64 text) — treated as unopenable


def _wrap_envelope(service_id: Any, blob: bytes) -> bytes:
    sid = str(service_id or "").encode("utf-8")
    return MAGIC_ENVELOPE + len(sid).to_bytes(2, "big") + sid + blob


def _unwrap_envelope(blob: bytes) -> tuple[Optional[str], bytes]:
    """Return (service_id or None, raw AEAD blob) from stored bytes."""
    if blob is None:
        return None, b""
    if isinstance(blob, memoryview):
        blob = blob.tobytes()
    blob = bytes(blob)
    if blob.startswith(MAGIC_ENVELOPE):
        try:
            size = int.from_bytes(blob[4:6], "big")
            sid = blob[6:6 + size].decode("utf-8")
            return sid, blob[6 + size:]
        except Exception:
            return None, blob
    # Legacy/dev blob (e.g. base64 text from a pre-envelope build): not
    # decryptable under the current format; callers fail closed.
    return None, blob


def _service_id_for_blob(blob: bytes) -> Optional[str]:
    """Which service a stored context blob belongs to (envelope metadata)."""
    try:
        sid, _ = _unwrap_envelope(blob)
        return sid
    except Exception:
        return None


def resolve_service_vault_key(*, override: Optional[str] = None) -> bytes:
    """Return the configured SERVICE_VAULT_KEY material.

    Resolution order: explicit override, keyring current key, environment variable, settings.
    Raises ``ServiceVaultKeyError`` when unset — callers must fail closed
    (ADR-0010: no fallback to unrestricted access).
    """
    # Explicit override takes precedence
    if override is not None:
        raw = override
    else:
        # Try keyring first
        try:
            _, key = current_master_key()
            return key
        except (ServiceVaultKeyMissing, ServiceVaultKeyUnreadable):
            pass

        # Fall back to env var / settings for backward compatibility
        raw = None
        try:
            from app.core.config import settings

            if SERVICE_VAULT_KEY_ENV in type(settings).__pydantic_fields__:
                raw = getattr(settings, SERVICE_VAULT_KEY_ENV, None)
        except Exception:  # pragma: no cover - settings import is always fine
            raw = None

        if raw is None:
            raw = os.environ.get(SERVICE_VAULT_KEY_ENV)

    if not raw:
        raise ServiceVaultKeyError(
            f"{SERVICE_VAULT_KEY_ENV} is not configured and no keyring available; "
            "service vault contexts are unavailable"
        )

    candidate = _normalize_key_material(raw)
    if (isinstance(raw, str) and len(raw) == _KEY_LENGTH * 2
            and all(c in "0123456789abcdefABCDEF" for c in raw)):
        candidate = bytes.fromhex(raw)

    if len(candidate) < _KEY_LENGTH:
        raise ServiceVaultKeyError(
            f"{SERVICE_VAULT_KEY_ENV} must provide at least {_KEY_LENGTH} bytes of key "
            f"material (got {len(candidate)}); refusing to derive service keys"
        )
    return candidate


def derive_data_key(master: bytes, service_id: Any) -> bytes:
    """HKDF-SHA256 domain separation: one data key per (SERVICE_VAULT_KEY, service)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        info=b"pysyspass-service-vault-v1",
        salt=str(service_id).encode("utf-8"),
    ).derive(master)


class _FlatCodec:
    """Pre-§13 flat context codec (SERVICE_VAULT_KEY direct derivation)."""

    def _derive(self, master: bytes, scope: Any) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_LENGTH,
            info=b"pysyspass-service-vault-v1",
            salt=str(scope or "").encode("utf-8"),
        ).derive(master)

    def _oneshot(self, dek: bytes, nonce: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_LENGTH,
            info=b"pysyspass-service-vault-oneshot-v1",
            salt=nonce,
        ).derive(dek)

    def seal(self, payload: dict[str, Any], service_id: Any,
             master: bytes, seal_nonce: Optional[bytes]) -> bytes:
        """Flat (pre-§13) seal: SERVICE_VAULT_KEY derives the context key."""
        if seal_nonce is not None:
            # DEK-codec layout (IMPL-014): bare service id as HKDF salt,
            # one-shot re-derivation from that same base key.
            base = self._derive(master, service_id)
            data_key = self._oneshot(base, seal_nonce)
            aad = b"oneshot|" + str(service_id or "").encode("utf-8") + b"|" + seal_nonce
            _ONE_SHOT_SEALS.add(seal_nonce)
        else:
            scope = seal_scope(service_id) if service_id else service_id
            aad = str(scope).encode("utf-8") if scope else b""
            data_key = self._derive(master, scope)
        iv = os.urandom(_IV_LENGTH)
        sealed = AESGCM(data_key).encrypt(
            iv, json.dumps(payload, sort_keys=True).encode("utf-8"), aad
        )
        envelope_sid = payload.get("service_id") or ""
        if seal_nonce is not None:
            envelope_sid = ""
        return _wrap_envelope(envelope_sid, iv + sealed)

    def open(self, raw_blob: bytes, scope: Any, nonce: Optional[bytes],
             master: bytes) -> dict[str, Any]:
        if nonce is not None:
            service_id = scope.replace("svc|", "") if str(scope).startswith("svc|") else scope
            aad = b"oneshot|" + str(service_id or "").encode("utf-8") + b"|" + nonce
            data_key = self._oneshot(self._derive(master, service_id), nonce)
        else:
            aad = str(scope).encode("utf-8") if scope else b""
            data_key = self._derive(master, scope)
        iv, sealed = raw_blob[:_IV_LENGTH], raw_blob[_IV_LENGTH:]
        plain = AESGCM(data_key).decrypt(iv, sealed, aad)
        result = json.loads(plain.decode("utf-8"))
        if nonce is not None:
            _ONE_SHOT_SEALS.discard(nonce)
            _ONE_SHOT_CONSUMED.add(nonce)
        return result


_FLAT = _FlatCodec()


def _keyring_active() -> bool:
    from app.core.service_vault_keyring import keyring_configured

    return keyring_configured()


def encrypt_service_vault_context(payload: dict[str, Any], service_id: Any,
                                  key: Optional[str] = None, *,
                                  seal_nonce: Optional[bytes] = None) -> bytes:
    """Encrypt a vault-context payload for ``service_id`` (AES-256-GCM).

    ``seal_nonce`` marks a single-shot seal: the payload (typically the
    master password) can then only be opened by a caller that presents the
    same nonce, and the seal is consumed on the first successful open (see
    ``decrypt_service_vault_context``).

    ADR-0010 §3 acceptance ruling (IMPL-010): with no explicitly configured
    keyring, the environment/settings SERVICE_VAULT_KEY seals contexts
    directly (flat derivation). With the operator-opt-in keyring active,
    contexts use per-service DEKs (§13 hierarchy) wrapped by the keyring
    master; both formats stay openable (envelope-compatible).
    """
    caller_key = _normalize_key_material(key) if key is not None else None
    if caller_key is not None and len(caller_key) < _KEY_LENGTH:
        raise ServiceVaultKeyError(
            f"{SERVICE_VAULT_KEY_ENV} must provide at least {_KEY_LENGTH} bytes of key "
            f"material (got {len(caller_key)}); refusing to derive service keys"
        )
    use_keyring = (caller_key is None) and _keyring_active()
    if not use_keyring:
        master = caller_key if caller_key is not None else resolve_service_vault_key()
        return _FLAT.seal(payload, service_id, master, seal_nonce)

    # Keyring hierarchy path: per-service DEK wrapped by the keyring master.
    try:
        dek_version, data_key = get_service_dek(service_id)
    except ServiceVaultKeyMissing:
        # Provision a new DEK for this service
        result = provision_service_dek(service_id)
        dek_version = result["dek_version"]
        _, data_key = get_service_dek(service_id)

    if seal_nonce is None and service_id:
        service_id = seal_scope(service_id)
    aad = str(service_id).encode("utf-8") if service_id else b""
    if seal_nonce is not None:
        # Derive a one-shot key from the DEK
        data_key = HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_LENGTH,
            info=b"pysyspass-service-vault-oneshot-v1",
            salt=seal_nonce,
        ).derive(data_key)
        aad = b"oneshot|" + str(service_id).encode("utf-8") + b"|" + seal_nonce
        _ONE_SHOT_SEALS.add(seal_nonce)
    iv = os.urandom(_IV_LENGTH)
    sealed = AESGCM(data_key).encrypt(
        iv, json.dumps(payload, sort_keys=True).encode("utf-8"), aad
    )
    envelope_sid = payload.get("service_id") or ""
    if seal_nonce is not None and envelope_sid:
        # Single-shot seals keep no readable envelope metadata: the consumer
        # presents the nonce (and thereby the payload) once.
        envelope_sid = ""
    return _wrap_envelope(envelope_sid, iv + sealed)


def decrypt_service_vault_context(blob: bytes, key_id: Any = None,
                                  key: Optional[str] = None) -> dict[str, Any]:
    """Decrypt a vault-context blob with the SERVICE_VAULT_KEY.

    ``key_id`` is the persisted ``encrypted_with_key`` identifier and must
    equal ``SERVICE_VAULT_KEY_INFO``. Key material: ``key`` when given, else
    the configured SERVICE_VAULT_KEY. Passing the master password as ``key``
    fails AEAD authentication: the context is not decryptable without the
    service vault key.

    Seals with a domain-separated key (``seal_scope`` = service id, or a
    single-shot ``seal_nonce``) must present the same scope to open. A
    single-shot seal is one-time readable: the sealing context is consumed on
    the first successful open, so the master password can never be re-read
    from disk after provisioning.
    """
    scope: Any = ""
    nonce: Optional[bytes] = None
    had_service_scope = False
    master_key_override: Optional[bytes] = None
    if isinstance(key_id, dict):
        # Internal cross-module form: {'aad': service_id} or {'nonce': bytes}.
        if "nonce" in key_id:
            nonce = bytes(key_id["nonce"])
        scope = key_id.get("aad", "")
        had_service_scope = True
        key_id = None
    if key_id is not None and not isinstance(key_id, (bytes, str)):
        # Positional convenience: decrypt(blob, service_vault_key).
        key, key_id = key_id, None
    if key_id is not None:
        stored = key_id.encode("utf-8") if isinstance(key_id, str) else bytes(key_id)
        if stored != SERVICE_VAULT_KEY_INFO:
            raise ServiceVaultContextDecryptError(
                "vault context is sealed with an unknown key identifier"
            )
        had_service_scope = True
    # The DEK codec seals a one-shot blob under the *bare* service id
    # (encrypt resolves the DEK before applying ``seal_scope``), so a caller
    # that presents the seal with an unsuffixed scope must fall back to the
    # raw scope for DEK resolution (IMPL-010 acceptance: seal and open must
    # agree on the DEK id; the AEAD tag still decides which attempt is right).
    nonce_dek_fallback = nonce is not None and bool(scope)
    # If a master key override is provided, normalize it for DEK unwrapping
    if key is not None and had_service_scope:
        master_key_override = _normalize_key_material(key)
    # Stored blobs are envelopes carrying the owning service id (public, not
    # secret); the AEAD derivation stays domain-separated per service, and an
    # external caller can open a blob with just (blob, key_id, key).
    envelope_sid, raw_blob = _unwrap_envelope(blob)
    if had_service_scope and not nonce and not scope and envelope_sid:
        scope = envelope_sid
    scope = seal_scope(scope) if (had_service_scope and not nonce and scope) else scope
    if nonce is not None and nonce not in _ONE_SHOT_SEALS:
        # A consumed seal stays dead for the rest of the process, even when
        # the same blob is re-presented through the codec fallback order.
        if nonce in _ONE_SHOT_CONSUMED:
            raise ServiceVaultContextDecryptError(
                "single-shot vault seal was already consumed"
            )
        # It must not be reported as "already consumed" while an AEAD failure
        # (wrong key/scope) is the real cause: only claim consumption once the
        # blob's codec is provably openable with the presented material. The
        # registry keeps seal nonces for the process lifetime after sealing;
        # IMPL-010's seal handoff is single-shot at the registry level, so a
        # nonce that was registered and later discarded by its one successful
        # open is dead for the rest of the process. The AEAD check below
        # discriminates a never-sealed blob (wrong master) from a genuinely
        # consumed seal.
        if key_id is not None or master_key_override is None:
            # Registered-seal case handled after the codec attempts: treat
            # the missing nonce optimistically here and enforce consumption
            # or authentication failure precisely below.
            pass
        else:
            raise ServiceVaultContextDecryptError(
                "single-shot vault seal was already consumed"
            )
    nonce_must_be_registered = nonce is not None and (
        key_id is not None or master_key_override is None
    )
    try:
        # Envelope-compatible open: try the flat (SERVICE_VAULT_KEY-direct)
        # codec first whenever the caller supplied the key or no keyring is
        # configured; fall back to the §13 DEK hierarchy, and vice versa. The
        # AEAD tag decides which codec sealed the blob — no ambiguity: a wrong
        # key/scope fails authentication rather than returning garbage.
        codecs: list = []
        if master_key_override is not None or not _keyring_active():
            flat_master = (master_key_override
                           if master_key_override is not None
                           else resolve_service_vault_key())
            codecs.append(("flat", flat_master))
            codecs.append(("dek", None))
        else:
            codecs.append(("dek", None))
            try:
                codecs.append(("flat", resolve_service_vault_key()))
            except ServiceVaultKeyError:
                pass
        last_error: Optional[Exception] = None
        saw_registered_seal = False
        for kind, flat_master in codecs:
            try:
                if kind == "flat":
                    if nonce is not None and nonce_must_be_registered:
                        if nonce not in _ONE_SHOT_SEALS:
                            # A seal that was registered and is no longer
                            # live was consumed by its one successful open.
                            saw_registered_seal = True
                            raise ServiceVaultContextDecryptError(
                                "single-shot vault seal was already consumed"
                            )
                        if nonce in _ONE_SHOT_CONSUMED:
                            # Same blob re-presented through the codec
                            # fallback order after a partial open.
                            raise ServiceVaultContextDecryptError(
                                "single-shot vault seal was already consumed"
                            )
                    return _FLAT.open(raw_blob, scope, nonce, flat_master)
                iv, sealed = raw_blob[:_IV_LENGTH], raw_blob[_IV_LENGTH:]
                if nonce is not None:
                    if nonce_must_be_registered:
                        if nonce not in _ONE_SHOT_SEALS:
                            saw_registered_seal = True
                            raise ServiceVaultContextDecryptError(
                                "single-shot vault seal was already consumed"
                            )
                        if nonce in _ONE_SHOT_CONSUMED:
                            raise ServiceVaultContextDecryptError(
                                "single-shot vault seal was already consumed"
                            )
                    dek_id = (scope.replace("svc|", "")
                              if str(scope).startswith("svc|") else "")
                    attempts = [dek_id]
                    if nonce_dek_fallback:
                        attempts.append(scope)
                    # A seal binds its AAD to the *bare* service id while the
                    # caller may present either spelling of the scope (and a
                    # deployment keyring can hold unrelated DEKs, e.g. under
                    # ''). A DEK that exists but fails the AEAD check is the
                    # wrong codec binding, not a terminal error: keep trying
                    # the remaining candidate ids; the tag decides.
                    from cryptography.exceptions import InvalidTag as _InvalidTag

                    dek_attempt_error: Optional[Exception] = None
                    for attempt in attempts:
                        try:
                            _, dek = get_service_dek(
                                attempt, master_key_override=master_key_override
                            )
                        except ServiceVaultKeyMissing:
                            continue
                        try:
                            candidate = HKDF(
                                algorithm=hashes.SHA256(),
                                length=_KEY_LENGTH,
                                info=b"pysyspass-service-vault-oneshot-v1",
                                salt=nonce,
                            ).derive(dek)
                            cand_aad = (b"oneshot|"
                                        + str(attempt or "").encode("utf-8")
                                        + b"|" + nonce)
                            plain = AESGCM(candidate).decrypt(
                                iv, sealed, cand_aad
                            )
                        except _InvalidTag as exc:
                            dek_attempt_error = exc
                            continue
                        data_key = candidate
                        aad = cand_aad
                        break
                    else:
                        if dek_attempt_error is not None:
                            raise dek_attempt_error
                        raise ServiceVaultKeyMissing(
                            f"no DEK for seal scope {scope!r}"
                        )
                else:
                    dek_id = (scope.replace("svc|", "")
                              if str(scope).startswith("svc|")
                              else (envelope_sid or ""))
                    _, data_key = get_service_dek(
                        dek_id, master_key_override=master_key_override
                    )
                    aad = str(scope).encode("utf-8") if scope else b""
                plain = AESGCM(data_key).decrypt(iv, sealed, aad)
                result = json.loads(plain.decode("utf-8"))
                if nonce is not None:
                    _ONE_SHOT_SEALS.discard(nonce)
                    _ONE_SHOT_CONSUMED.add(nonce)
                return result
            except ServiceVaultContextDecryptError:
                raise
            except Exception as exc:  # AEAD failure -> try the other codec
                last_error = exc
        if saw_registered_seal:
            raise ServiceVaultContextDecryptError(
                "single-shot vault seal was already consumed"
            )
        raise ServiceVaultContextDecryptError(
            "service vault context failed authentication/decryption"
        ) from last_error
    except ServiceVaultKeyMissing as exc:
        raise ServiceVaultContextDecryptError(
            f"service vault context failed authentication/decryption: {exc}"
        ) from exc
    except Exception as exc:
        raise ServiceVaultContextDecryptError(
            f"service vault context failed authentication/decryption: {exc}"
        ) from exc


# ─── Key Hierarchy Management (IMPL-014) ─────────────────────────────────

def rotate_service_vault_master_key(new_key_id: str) -> dict:
    """Rotate the master SERVICE_VAULT_KEY and rewrap all service DEKs.
    
    This implements the 'On Service Key Change' procedure from ADR-0010 §13 as amended by §17:
    1. Add new master key version to keyring
    2. Rewrap all service DEKs with the new master key
    3. Old key retained for historical context decryption
    
    Returns info about the rotation.
    """
    from app.core.service_vault_keyring import rotate_master_key
    
    # Add new master key version
    rotate_result = rotate_master_key(new_key_id)
    
    # Rewrap all service DEKs with the new master key
    rewrap_result = rewrap_all_service_deks(new_key_id)
    
    return {
        "master_key_rotation": rotate_result,
        "dek_rewrap": rewrap_result,
    }


def rotate_service_context_key(service_id: str) -> dict:
    """Rotate the DEK for a specific service (independent rotation per ADR-0010 §13).
    
    This generates a new DEK for the service wrapped with the current master key.
    The old DEK version is retained in the keyring for decrypting existing contexts.
    
    Returns info about the rotation.
    """
    from app.core.service_vault_keyring import rotate_service_dek
    
    return rotate_service_dek(service_id)


def rewrap_service_context_key(service_id: str, new_master_key_id: str) -> dict:
    """Rewrap a service's DEK with a different master key version.
    
    Used during master key rotation to migrate a specific service's DEK.
    """
    return rewrap_service_deks(service_id, new_master_key_id)


__all__ = [
    "SERVICE_VAULT_KEY_INFO",
    "SERVICE_VAULT_CONTEXT_VERSION",
    "SERVICE_VAULT_KEY_ENV",
    "ServiceVaultKeyError",
    "ServiceVaultContextDecryptError",
    "resolve_service_vault_key",
    "derive_data_key",
    "encrypt_service_vault_context",
    "decrypt_service_vault_context",
    # Key hierarchy management (IMPL-014)
    "rotate_service_vault_master_key",
    "rotate_service_context_key",
    "rewrap_service_context_key",
]