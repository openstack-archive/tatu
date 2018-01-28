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
        ZONE = DESIGNATE.zones.get(CONF.tatu.pat_dns_zone_name)


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


def get_srv_url(hostname, project):
    return '_ssh._tcp.{}.{}.{}'.format(hostname, project, ZONE['name'])


def delete_srv_records(srv_url):
    try:
        DESIGNATE.recordsets.delete(ZONE['id'], srv_url)
    except:
        pass


def add_srv_records(hostname, project, ip_port_tuples):
    records = []
    for ip, port in ip_port_tuples:
        bastion = bastion_name_from_ip(ip)
        # SRV record format is: priority weight port A-name
        records.append(
            '10 50 {} {}'.format(port, bastion))
    srv_url = get_srv_url(hostname, project)
    try:
        DESIGNATE.recordsets.create(ZONE['id'], srv_url, 'SRV', records)
    except Conflict:
        pass
    return  srv_url


_setup_zone()
