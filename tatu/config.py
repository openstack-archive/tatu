#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from castellan.common import utils as castellan_utils
from castellan.options import set_defaults as set_castellan_defaults
from designateclient.v2 import client as designate_client
from keystoneauth1 import session as keystone_session
from keystoneauth1.identity import v3
from keystoneclient.v3 import client as keystone_client
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
from oslo_config import cfg
from oslo_context import context
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# 1) register options; 2) read the config file; 3) use the options
opts = [
    cfg.BoolOpt('pam_sudo', default=False,
                help='Use pam-ussh module to validate certificates on sudo calls'),
    cfg.BoolOpt('use_barbican', default=False,
                help='Use OpenStack Barbican to store sensitive data'),
    cfg.BoolOpt('use_pat_bastions', default=True,
                help='Use PAT as a "poor man\'s" approach to bastions'),
    cfg.IntOpt('ssh_port', default=2222,
                help='SSH server port number managed by Tatu (may be other than 22)'),
    cfg.IntOpt('num_total_pats', default=3,
                help='Number of available PAT addresses for bastions'),
    cfg.IntOpt('num_pat_bastions_per_server', default=2,
                help='Number of PAT bastions per server for redundancy'),
    cfg.StrOpt('pat_dns_zone_name',
               default='tatuPAT.com.',
               help='Name of DNS zone for A and SRV records for PAT bastions'),
    cfg.StrOpt('pat_dns_zone_email',
               default='tatu@nono.nono',
               help='Email of admin for DNS zone for PAT bastions'),
    cfg.StrOpt('sqlalchemy_engine',
               default='mysql+pymysql://root:pinot@127.0.0.1/tatu',
               help='SQLAlchemy database URL'),
    cfg.StrOpt('auth_url',
               default='http://localhost/identity/v3',
               help='OpenStack Keystone URL'),
    cfg.StrOpt('user_id',
               default='fab01a1f2a7749b78a53dffe441a1879',
               help='OpenStack Keystone admin privileged user-id'),
    cfg.StrOpt('password',
               default='pinot',
               help='OpenStack Keystone password'),
    cfg.StrOpt('project_id',
               default='2e6c998ad16f4045821304470a57d160',
               help='OpenStack Keystone admin project UUID'),
    cfg.StrOpt('api_endpoint_for_vms',
               default='http://169.254.169.254',
               help='Where a VM accesses the API for SSH certs and revoked keys'),
    cfg.StrOpt('api_base_uri',
               default='http://169.254.169.254',
               help='Base URI for version discovery.'),
]

CONF = cfg.ConfigOpts()
CONF.register_opts(opts, group='tatu')

logging.register_options(CONF)
log_levels = logging.get_default_log_levels() + \
             ['tatu=DEBUG', '__main__=DEBUG']
logging.set_defaults(default_log_levels=log_levels)

CONF(args=[], default_config_files=['/etc/tatu/tatu.conf'])
logging.setup(CONF, "tatu")

GCONF = cfg.CONF

if CONF.tatu.use_barbican:
    LOG.debug("Using Barbican as key manager.")
    set_castellan_defaults(GCONF)
else:
    LOG.debug("Using Tatu as key manager.")
    set_castellan_defaults(GCONF,
                           api_class='tatu.castellano.TatuKeyManager')

global_config_files = ['/etc/tatu/tatu.conf']
if CONF.tatu.use_pat_bastions:
    from dragonflow import conf as dragonflow_cfg
    from dragonflow.db import api_nb
    global_files.append('/etc/neutron/dragonflow.ini')

GCONF(args=[], default_config_files=global_config_files)

auth = v3.Password(auth_url=CONF.tatu.auth_url,
                   user_id=CONF.tatu.user_id,
                   password=CONF.tatu.password,
                   project_id=CONF.tatu.project_id)
session = keystone_session.Session(auth=auth)
KEYSTONE = keystone_client.Client(session=session)
NOVA = nova_client.Client('2', session=session)
NEUTRON = neutron_client.Client(session=session)
DESIGNATE = designate_client.Client(session=session)

DRAGONFLOW = None
if CONF.tatu.use_pat_bastions:
    dragonflow_cfg.CONF.set_override('enable_df_pub_sub', False, group='df')
    DRAGONFLOW = api_nb.NbApi.get_instance(False)

# Create a context for use by Castellan
CONTEXT = castellan_utils.credential_factory(conf=CONF)
