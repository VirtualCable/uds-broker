# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 Virtual Cable S.L.
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
import dataclasses
import datetime
import typing

from uds.core.util.model import sql_now

if typing.TYPE_CHECKING:
    from uds.models import UserService


# TODO: Remove old format comments
# 'u': userservice.user.uuid if userservice.user else '',
# 's': userservice.uuid,
# 'h': host,
# 'p': port,
# 'e': extra,
@dataclasses.dataclass(frozen=True)
class TunnelTicket:
    """Dataclass that represents a tunnel ticket"""

    userservice: 'UserService | None'
    host: str
    port: int
    extra: dict[str, str] = dataclasses.field(default_factory=dict[str, str])
    started: datetime.datetime = dataclasses.field(default_factory=sql_now)
    shared_secret: bytes | None = None

    def to_dict(self) -> dict[str, str]:
        """Returns a dict representation of the ticket"""
        return {
            'userservice_uuid': self.userservice.uuid if self.userservice else '',
            'host': self.host,
            'port': str(self.port),
            'extra': '' if not self.extra else ','.join(f'{k}={v}' for k, v in self.extra.items()),
            'started': str(int(self.started.timestamp())),
            'shared_secret': self.shared_secret.hex() if self.shared_secret else '',
        }

    @staticmethod
    def from_dict(data: dict[str, str]) -> 'TunnelTicket':
        # Import here to avoid circular imports, global is only for type checking
        from uds.models import UserService

        """Creates a ticket from a dict representation"""
        userservice = (
            UserService.objects.filter(uuid=data['userservice_uuid']).first()
            if data['userservice_uuid']
            else None
        )
        return TunnelTicket(
            userservice=userservice,
            host=data['host'],
            port=int(data['port']),
            extra=({} if data['extra'] == '' else dict(item.split('=') for item in data['extra'].split(','))),
            started=datetime.datetime.fromtimestamp(int(data['started'])),
            shared_secret=bytes.fromhex(data['shared_secret']) if data['shared_secret'] else None,
        )


@dataclasses.dataclass
class TunnelTicketResponse:
    """Dataclass that represents a tunnel ticket response"""

    host: str
    port: int
    notify: str
    shared_secret: str | None

    def as_dict(self) -> dict[str, str | int]:
        """Returns a dict representation of the ticket response"""
        return {
            'host': self.host,
            'port': self.port,
            'notify': self.notify,
            'shared_secret': self.shared_secret if self.shared_secret else '',
        }

    @staticmethod
    def from_dict(data: dict[str, typing.Any]) -> 'TunnelTicketResponse':
        """Creates a ticket response from a dict representation"""
        return TunnelTicketResponse(
            host=data['host'],
            port=int(data['port']),
            notify=data['notify'],
            shared_secret=data['shared_secret'] if data['shared_secret'] else None,
        )
