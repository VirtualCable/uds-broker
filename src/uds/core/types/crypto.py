import dataclasses


@dataclasses.dataclass
class TunnelMaterial:
    key_payload: bytes    # 32 bytes
    key_send: bytes       # 32 bytes
    key_receive: bytes    # 32 bytes
    nonce_send: bytes     # 12 bytes, used for payload and send to tunnel
    nonce_receive: bytes  # 12 bytes
