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

from designateclient.v2 import client as designate_client
from dragonflow import conf as dragonflow_cfg
from dragonflow.db import api_nb
from keystoneauth1 import session as keystone_session
from keystoneauth1.identity import v3
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
from oslo_config import cfg
from oslo_context import context
from oslo_log import log as logging
from castellan.options import set_defaults as set_castellan_defaults

LOG = logging.getLogger(__name__)

# 1) register options; 2) read the config file; 3) use the options
opts = [
    cfg.BoolOpt('use_barbican_key_manager', default=False,
                help='Use OpenStack Barbican to store sensitive data'),
    cfg.BoolOpt('use_pat_bastions', default=True,
                help='Use PAT as a "poor man\'s" approach to bastions'),
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
               default='mysql+pymysql://root:pinot@127.0.0.1',
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
]

CONF = cfg.CONF
CONF.register_opts(opts, group='tatu')

logging.register_options(CONF)
log_levels = logging.get_default_log_levels() + \
             ['tatu=DEBUG', '__main__=DEBUG']
logging.set_defaults(default_log_levels=log_levels)


try:
    CONF(args=[], default_config_files=['/etc/tatu/tatu.conf',
                                       'files/tatu.conf',
                                       '/etc/neutron/dragonflow.ini'])
except Exception as e:
    LOG.error("Failed to load configuration file: {}".format(e))
 
logging.setup(CONF, "tatu")
if CONF.tatu.use_barbican_key_manager:
    LOG.debug("Using Barbican as key manager.")
    set_castellan_defaults(CONF)
else:
    LOG.debug("Using Tatu as key manager.")
    set_castellan_defaults(CONF,
                           api_class='tatu.castellano.TatuKeyManager')

auth = v3.Password(auth_url=CONF.tatu.auth_url,
                   user_id=CONF.tatu.user_id,
                   password=CONF.tatu.password,
                   project_id=CONF.tatu.project_id)
session = keystone_session.Session(auth=auth)
NOVA = nova_client.Client('2', session=session)
NEUTRON = neutron_client.Client(session=session)
DESIGNATE = designate_client.Client(session=session)

dragonflow_cfg.CONF.set_override('enable_df_pub_sub', False, group='df')
DRAGONFLOW = api_nb.NbApi.get_instance(False)

# Create a context for use by Castellan
CONTEXT = context.RequestContext(auth_token=auth.get_token(session),
                                 tenant=auth.get_project_id(session))
