import dataclasses


@dataclasses.dataclass
class TunnelMaterial:
    key_payload: bytes
    key_send: bytes
    key_receive: bytes
    nonce_send: bytes
    nonce_receive: bytes
