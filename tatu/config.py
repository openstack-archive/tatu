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

from oslo_config import cfg
from oslo_log import log as logging
from castellan.options import set_defaults as set_castellan_defaults
from tatu import castellano
import sys

LOG = logging.getLogger(__name__)
# 3 steps: register options; read the config file; use the options

opts = [
    cfg.BoolOpt('use_barbican_key_manager', default=False,
                help='Enable the usage of the OpenStack Key Management '
                     'service provided by barbican.'),
]

DOMAIN = "tatu"
CONF = cfg.CONF
CONF.register_opts(opts, group='tatu')

logging.register_options(CONF)
log_levels = logging.get_default_log_levels() + \
             ['tatu=DEBUG', '__main__=DEBUG']
logging.set_defaults(default_log_levels=log_levels)
#CONF(default_config_files=cfg.find_config_files(project='tatu', prog='tatu'))

try:
    CONF(args=[], default_config_files=['files/tatu.conf'])
except Exception as e:
    LOG.error("Failed to load configuration file: {}".format(e))
 
logging.setup(CONF, DOMAIN)
if CONF.tatu.use_barbican_key_manager:
    LOG.debug("Using Barbican as key manager.")
    set_castellan_defaults(CONF)
else:
    LOG.debug("Using Tatu as key manager.")
    set_castellan_defaults(CONF,
                           api_class='tatu.castellano.TatuKeyManager')

