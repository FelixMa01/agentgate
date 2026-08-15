"""Ed25519-signed audit receipts.

Each audit event gets a receipt: a signed envelope over (prev_receipt,
chain_hash, action, event_json). The signed JSON proves to an external
verifier that AgentGate produced a specific audit entry — inspired by
luckyPipewrench/pipelock's mediator-signed receipts.

Keys are auto-generated into ~/.agentgate/receipts/ on first use.
The verifier CLI exposes ``agentgate receipts verify <audit.db>``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RECEIPTS_DIR = Path.home() / ".agentgate" / "receipts"


@dataclass
class ReceiptKeyPair:
    private_path: Path
    public_path: Path
    key_id: str

    @classmethod
    def load_or_create(cls, key_id: str = "primary") -> ReceiptKeyPair:
        RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
        priv = RECEIPTS_DIR / f"{key_id}.ed25519.pem"
        pub = RECEIPTS_DIR / f"{key_id}.ed25519.pub.pem"
        if not priv.exists():
            sk = Ed25519PrivateKey.generate()
            priv.write_bytes(
                sk.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            pub.write_bytes(
                sk.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            priv.chmod(0o600)
        return cls(priv, pub, key_id)


def _sign_payload(payload: bytes, keypair: ReceiptKeyPair) -> str:
    sk = serialization.load_pem_private_key(keypair.private_path.read_bytes(), password=None)
    sig = sk.sign(payload)  # type: ignore[union-attr]
    return base64.b64encode(sig).decode()


def _verify_payload(payload: bytes, signature_b64: str, public_path: Path) -> bool:
    pk = serialization.load_pem_public_key(public_path.read_bytes())
    sig = base64.b64decode(signature_b64)
    try:
        pk.verify(sig, payload)  # type: ignore[union-attr]
        return True
    except InvalidSignature:
        return False


def receipt_envelope(
    *,
    prev_receipt_signature: str | None,
    chain_hash: str,
    action: str,
    event: dict,
    keypair: ReceiptKeyPair | None = None,
) -> dict:
    """Build a signed receipt envelope."""
    kp = keypair or ReceiptKeyPair.load_or_create()
    payload_dict = {
        "prev_signature": prev_receipt_signature,
        "chain_hash": chain_hash,
        "action": action,
        "event": event,
    }
    payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode()
    sig = _sign_payload(payload, kp)
    return {
        "key_id": kp.key_id,
        "payload": payload_dict,
        "signature": sig,
        "fingerprint": hashlib.sha256(payload).hexdigest()[:16],
    }


def verify_receipt(receipt: dict, public_path: Path) -> bool:
    """Verify a single receipt's signature against a public key."""
    payload = json.dumps(
        receipt["payload"], sort_keys=True, separators=(",", ":")
    ).encode()
    return _verify_payload(payload, receipt["signature"], public_path)
