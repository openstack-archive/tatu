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
import json
from oslo_log import log as logging
from tatu.api import models
from tatu.config import CONF
from tatu.db.persistence import SQLAlchemySessionManager

LOG = logging.getLogger(__name__)

_versions = []
_base = CONF.tatu.api_base_uri.rstrip('/')

def _version(version, status, base_uri):
    _versions.append({
        'id': '%s' % version,
        'status': status,
        'links': [{
            'href': base_uri + '/' + version,
            'rel': 'self'
        }]
    })

_version('v1', 'CURRENT', _base)

class Versions(object):

    def on_get(self, req, resp):
        body = {
            'versions': {
                'values': _versions
            },
        }
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK

class Version1(object):

    def on_get(self, req, resp):
        body = {
            'version': _versions[0],
        }
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK


def create_app(sa):
    LOG.info("Creating falcon API instance for authenticated API calls.")
    api = falcon.API(middleware=[models.Logger(), sa])
    api.add_route('/v1/authorities', models.Authorities())
    api.add_route('/v1/authorities/{auth_id}', models.Authority())
    api.add_route('/v1/usercerts', models.UserCerts())
    api.add_route('/v1/usercerts/{serial}', models.UserCert())
    api.add_route('/v1/hosts', models.Hosts())
    api.add_route('/v1/hosts/{host_id}', models.Host())
    api.add_route('/v1/hostcerts', models.HostCerts())
    api.add_route('/v1/hostcerts/{host_id}/{fingerprint}', models.HostCert())
    api.add_route('/v1/hosttokens', models.Tokens())
    api.add_route('/v1/novavendordata', models.NovaVendorData())
    api.add_route('/v1/revokeduserkeys/{auth_id}', models.RevokedUserKeys())
    api.add_route('/v1/pats', models.PATs())
    api.add_route('/v1', Version1())
    api.add_route('/', Versions())
    return api

def create_noauth_app(sa):
    LOG.info("Creating falcon API instance for unauthenticated API calls.")
    api = falcon.API(middleware=[models.Logger(), sa])
    api.add_route('/hostcerts', models.HostCerts())
    api.add_route('/revokeduserkeys/{auth_id}', models.RevokedUserKeys())
    api.add_route('/v1', Version1())
    api.add_route('/', Versions())
    return api

def auth_factory(global_config, **settings):
    return create_app(SQLAlchemySessionManager())

def noauth_factory(global_config, **settings):
    return create_noauth_app(SQLAlchemySessionManager())
