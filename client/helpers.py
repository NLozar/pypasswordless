from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64
import json

def verifyAndParseToken(token_str: str) -> dict:
	token: dict = json.loads(token_str)
	payload_string: str = token["payload"]
	payload: dict = json.loads(payload_string)
	sig: bytes = base64.b64decode(token["signature"].encode("utf-8"))
	servicePublicKey: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(base64.b64decode(payload["publicKey"].encode("utf-8")))
	servicePublicKey.verify(sig, payload_string.encode("utf-8"))
	return payload
