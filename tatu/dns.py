# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
from designateclient.exceptions import Conflict
from oslo_log import log as logging

from tatu.config import CONF, DESIGNATE

LOG = logging.getLogger(__name__)
ZONE = None


def _setup_zone():
    try:
        global ZONE
        ZONE = DESIGNATE.zones.create(CONF.tatu.pat_dns_zone_name,
                                      email=CONF.tatu.pat_dns_zone_email)
    except Conflict:
        pass


def bastion_name_from_ip(ip_address):
    return "bastion-{}.{}".format(ip_address.replace('.', '-'),
                                  ZONE['name'])


def register_bastion(ip_address):
    try:
        DESIGNATE.recordsets.create(ZONE['id'],
                                    bastion_name_from_ip(ip_address),
                                    'A', [ip_address])
    except Conflict:
        pass


def sync_bastions(ip_addresses):
    for ip in ip_addresses:
        register_bastion(ip)


def add_srv_records(hostname, project_id, port_ip_tuples):
    records = []
    for port, ip in port_ip_tuples:
        bastion = bastion_name_from_ip(ip)
        # SRV record format is: priority weight port A-name
        records.add(
            '10 50 {} {}'.format(port, bastion))

    DESIGNATE.recordsets.create(ZONE['id'],
                                '_ssh._tcp.{}.{}'.format(hostname,
                                                         project_id[:8]),
                                'SRV', records)


_setup_zone()
