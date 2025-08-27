from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64
import json

def verifyAndParseReqData(payload_str: str, sig_str: str) -> dict:
	payload: dict = json.loads(payload_str)
	sig: bytes = base64.b64decode(sig_str.encode("utf-8"))
	servicePublicKey: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(base64.b64decode(payload["userPublicKey"].encode("utf-8")))
	servicePublicKey.verify(sig, payload_str.encode("utf-8"))
	return payload
