# Copyright (c) 2019-2026 Virtual Cable S.L.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#    * Neither the name of Virtual Cable S.L. nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
Author: Adolfo Gómez, dkmaster at dkmon dot com
"""
# Unified KEM interface for OpenUDS

import base64
import typing

# Note, clients must use the same KEM module (kyber512, kyber768, kyber1024)
from pqcrypto.kem import ml_kem_1024 as kyber

def encrypt(kem_key_b64: str) -> tuple[bytes, bytes]:
    """
    Given a base64-encoded KEM public key, generates a shared secret and ciphertext.

    Returns a tuple of (shared_secret: bytes, ciphertext: bytes)
    """
    kem_key = base64.b64decode(kem_key_b64)

    if len(kem_key) != typing.cast(int, kyber.PUBLIC_KEY_SIZE):  # pyright: ignore[reportUnknownMemberType]
        raise ValueError(
            f"KEM key must be {kyber.PUBLIC_KEY_SIZE} bytes"  # pyright: ignore[reportUnknownMemberType]
        )

    ciphertext, shared_secret = kyber.encrypt(kem_key)  # pyright: ignore[reportUnknownMemberType]

    return shared_secret, ciphertext
