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

import falcon
import os.path
from oslo_config import cfg

import models
from tatu.castellano import validate_config as validate_castellan_config
from tatu.db.persistence import SQLAlchemySessionManager

validate_castellan_config()
fname = 'tatu.conf'
CONF = cfg.CONF
if os.path.isfile(fname):
    CONF(default_config_files=[fname])


def create_app(sa):
    api = falcon.API(middleware=[models.Logger(), sa])
    api.add_route('/authorities', models.Authorities())
    api.add_route('/authorities/{auth_id}', models.Authority())
    api.add_route('/usercerts', models.UserCerts())
    api.add_route('/usercerts/{user_id}/{fingerprint}', models.UserCert())
    api.add_route('/hostcerts', models.HostCerts())
    api.add_route('/hostcerts/{host_id}/{fingerprint}', models.HostCert())
    api.add_route('/hosttokens', models.Tokens())
    api.add_route('/novavendordata', models.NovaVendorData())
    return api


def get_app():
    return create_app(SQLAlchemySessionManager())


def main(global_config, **settings):
    return create_app(SQLAlchemySessionManager())
