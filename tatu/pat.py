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

from dragonflow.db.models.core import Chassis
from dragonflow.db.models.l2 import LogicalPort
from dragonflow.db.models.l2 import LogicalRouter
from dragonflow.db.models.l3 import PAT
from dragonflow.db.models.l3 import PATEntry
from oslo_log import log as logging
import random
from tatu import dns
from tatu.config import CONF, NEUTRON, NOVA, DRAGONFLOW
from tatu.db import models as tatu_db

LOG = logging.getLogger(__name__)
PATS = DRAGONFLOW.get_all(PAT)

def _sync_pats():
    # TODO(pino): re-bind PATs when hypervisors fail (here and on notification)
    all_chassis = DRAGONFLOW.get_all(Chassis)
    # Filter the chassis that already have PATS assigned
    free_chassis = set(all_chassis).difference(p.chassis for p in PATS)
    # Don't make more PATs than there are free chassis
    num_to_make = min(CONF.tatu.num_total_pats - len(PATS),
                      len(free_chassis))
    if num_to_make <= 0:
        return
    assigned_chassis = random.sample(free_chassis, num_to_make)
    for c in assigned_chassis:
        _add_pat(c)
    dns.sync_bastions(str(p.ip_address) for p in PATS)


def _add_pat(chassis):
    # Find the public network and allocate a new port.
    networks = NEUTRON.list_networks(name='public')
    network_id = networks['networks'][0]['id']
    body = {
        "port": {
            "admin_state_up": True,
            "name": 'TatuPAT', # TODO(pino): set device owner to Tatu?
            "network_id": network_id,
        }
    }
    neutron_port = NEUTRON.create_port(body)
    lport = DRAGONFLOW.get(LogicalPort(id=neutron_port['port']['id']))
    ip = get_ip4_from_lport(lport)
    pat = PAT(
        id = str(ip),
        topic = 'tatu', # TODO(pino): What topic? Admin project_id?
        ip_address = ip,
        lport = lport
    )
    # We only need to store the PAT in dragonflow's DB, not API/MySQL
    DRAGONFLOW.create(pat)
    PATS.append(pat)


def _get_ip4_from_lport(lport):
    for ip in lport.ips:
        if ip.version is 4:
            return ip
    return None


def df_find_lrouter_by_lport(lport):
    lrouters = DRAGONFLOW.get_all(LogicalRouter)
    for lr in lrouters:
        for lp in lr.ports:
            if lp.lswitch.id == lport.lswitch.id:
                return lr
    return None

def create_pat_entries(sql_session, instance_id, fixed_l4_port,
                       num=CONF.tatu.num_pat_bastions_per_server):
    port_ip_tuples = []
    server = NOVA.servers.get(instance_id)
    ifaces = server.interface_list()
    for iface in ifaces:
        lport = DRAGONFLOW.get(LogicalPort(id=iface['port_id']))
        # TODO(pino): no router? consider SNAT of source IP to 169.254.169.254
        lrouter = df_find_lrouter_by_lport(lport)
        if lrouter is None: continue
        # Reserve N l4 ports on distinct IPs.
        pats = PATS
        if (num < len(PATS)):
            pats = random.sample(pats, num)
        for pat in pats:
            pat_l4_port = tatu_db.reserve_l4_port(sql_session, str(pat.ip))
            pat_entry = PATEntry(
                pat = pat,
                pat_l4_port = pat_l4_port,
                fixed_ip_address = _get_ip4_from_lport(lport),
                fixed_l4_port = fixed_l4_port,
                lport = lport,
                lrouter = df_fields.ReferenceField(LogicalRouter),
            )
            DRAGONFLOW.create(pat_entry)
            port_ip_tuples.append((pat_l4_port, str(pat.ip)))
        # if we got here, we now have the required pat_entries
        break
    return port_ip_tuples


_sync_pats()