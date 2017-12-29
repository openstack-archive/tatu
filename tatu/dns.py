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
from designateclient.v2 import client
from keystoneclient import session
from keystoneclient.auth.identity.generic.password import Password
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

auth = Password(auth_url=os.getenv('OS_AUTH_URL'),
                username=os.getenv('OS_USERNAME'),
                password=os.getenv('OS_PASSWORD'),
                project_name=os.getenv('OS_PROJECT_NAME'),
                project_domain_id='default',
                user_domain_id='default')

s = session.Session(auth=auth)

client = client.Client(session=s)
zone = None
bastions = {}


def setup(bastions=[]):
    # TODO: retrieve the zone name and email from configuration
    try:
        global zone
        zone = client.zones.create('julia.com.', email='pino@yahoo.com')
    except Conflict:
        pass

        # TODO: fetch all existing bastions


def add_bastion(ip_address, project_id, project_name, num):
    bastion_name = "{}-{}-{}.{}".format(str(project_id)[:8], project_name, num,
                                        zone['name'])
    client.recordsets.create(zone['id'], bastion_name, 'A', [ip_address])
    bastions.add(ip_address, bastion_name)
    return bastion_name


def add_srv_records(project_id, hostname, pat_entries):
    records = []
    for pat_entry in pat_entries:
        b = bastions[pat_entries.pat.ip_address]
        # SRV record format is: priority weight port A-name
        records.add(
            '10 50 {} {}'.format(pat_entry.pat_l4_port, b))

    client.recordsets.create(zone['id'],
                             'ssh.{}.{}'.format(hostname, project_id[:8]),
                             'SRV', records)
