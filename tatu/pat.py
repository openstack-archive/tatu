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

from dragonflow.db import api_nb
from dragonflow.db.models import l3
from oslo_log import log
from neutronclient.v2_0 import client
from novaclient import client
import random
from tatu.db import models as db

# Need to load /etc/neutron/dragonflow.ini
# config.init(sys.argv[1:])
dragonflow = api_nb.NbApi.get_instance(False)

def add_pat():
    # First choose a host where the PAT will be bound.
    nova = client.Client(VERSION, USERNAME, PASSWORD, PROJECT_ID, AUTH_URL)
    hosts = nova.servers.list()
    host_id = random.sample(hosts, 1)[0].id

    # Now create the new port on the public network.
    neutron = client.Client(username=USER,
                            password=PASS,
                            project_name=PROJECT_NAME,
                            auth_url=KEYSTONE_URL)

    # Find the public network and allocate 2 ports.
    networks = neutron.list_networks(name='public')
    network_id = networks['networks'][0]['id']

    body_value = {
        "port": {
            "admin_state_up": True,
            "name": TatuPAT,
            "network_id": network_id,
            "binding: host_id": host_id
        }
    }
    pat_lport = neutron.create_port()
    # TODO: Bind the port to a specific host

    pat = l3.PAT(
        topic = 'foo',
        ip_address = pat_lport.ip,
        lport = pat_lport
    )
    dragonflow.create(pat)
    db.add_pat(pat.lport)
    return pat_lport.ip


# At startup, we create 1 PAT if none exists
if not db.get_pats():
    add_pat()

# TODO(pino): need to re-bind PATs when hosts fail.


def create_pat_entries(instance_id, fixed_l4_port, num=2):
    # TODO(pino): Use Neutron client to find a suitable lport on the instance
    lport = None
    lrouter = None
    # Reserve N assignments (i.e. IP:port pairs) on distinct IPs.
    pats = db.get_pats()
    pat_entries = set()
    if (num < len(pats)):
        pats = random.sample(pats, num_assignments)
    for pat in pats:
        pat_l4_port = db.reserve_l4_port(pat.ip, lport.id, lport.ip, fixed_l4_port)
        pat_entry = l3.PATEntry(
            pat = pat,
            pat_l4_port = pat_l4_port,
            fixed_ip_address = lport.ip,
            fixed_l4_port = fixed_l4_port,
            lport = lport,
            lrouter = df_fields.ReferenceField(LogicalRouter),
        )
        dragonflow.create(pat_entry)
        pat_entries.add(pat_entry)
    return pat_entries
