# -*- coding: utf-8 -*-
#
# Copyright (c) 2024 Virtual Cable S.L.
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
import logging

# from unittest import mock

from uds.core import types
from uds import models
from uds.core.util.model import sql_now

from tests.utils import rest


logger = logging.getLogger(__name__)


class TicketTest(rest.test.RESTTestCase):
    """
    Test ticket functionality
    """

    server_token: str
    valid_ticket: str

    def setUp(self) -> None:
        super().setUp()

        sg = models.ServerGroup.objects.create(
            name='Test Tunnel Group', type=types.servers.ServerType.TUNNEL.value, subtype=''
        )

        # Create a ticket server
        server = models.Server.objects.create(
            register_username='tester',
            register_ip='127.0.0.1',
            ip='127.0.0.1',
            hostname='localhost',
            type=types.servers.ServerType.TUNNEL.value,
            stamp=sql_now(),
            subtype='',
        )
        server.groups.add(sg)
        self.server_token = server.token

        # Create a valid ticket for testing
        self.valid_ticket = models.TicketStore.create_for_tunnel(
            self.user_services[0], 1234, 'localhost', extra={'foo': 'bar'}
        )
        # Store a shared secret (32 bytes)
        models.TicketStore.set_shared_secret(self.valid_ticket, b'\x01' * 32)

    @staticmethod
    def get_url(ticket: str, token: str, msg: str) -> str:
        """
        Returns the URL for ticket requests
        """
        return f'/uds/rest/tunnel/ticket/{ticket}/{msg}/{token}'

    def test_request_invalid_token(self) -> None:
        """
        Test ticket request with invalid token
        """
        response = self.client.get(
            self.get_url(
                self.valid_ticket,
                'invalid_token',
                '127.0.0.1',
            ),
        )
        self.assertEqual(response.status_code, 403)
        
    def test_request_invalid_ticket(self) -> None:
        """
        Test ticket request with invalid ticket
        """
        response = self.client.get(
            self.get_url(
                'invalid_ticket',
                self.server_token,
                '127.0.0.1',
            ),
        )
        self.assertEqual(response.status_code, 403)


    def test_request_valid_ticket_start(self) -> None:
        """
        Test ticket request with valid ticket and start
        """
        response = self.client.get(
            self.get_url(
                self.valid_ticket,
                self.server_token,
                '127.0.0.1', # Start message is the source IP, compat with 4.x
            ),
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        r = types.tickets.TunnelTicketResponse.from_dict(data)  # Just to check it can be created without errors

        self.assertEqual(r.host, 'localhost')
        self.assertEqual(r.port, 1234)
        self.assertIsInstance(r.notify, str)
        self.assertEqual(r.shared_secret, '01' * 32)  # Hex representation
