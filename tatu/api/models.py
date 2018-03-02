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
import logging
import uuid
from Crypto.PublicKey import RSA
from oslo_log import log as logging

from tatu.config import CONF
from tatu.db import models as db
from tatu.dns import add_srv_records
from tatu.ks_utils import getProjectRoleNames, getProjectNameForID, getUserNameForID
from tatu.utils import canonical_uuid_string, datetime_to_string

if CONF.tatu.use_pat_bastions:
    from tatu.pat import create_pat_entries, getAllPats, ip_port_tuples_to_string

LOG = logging.getLogger(__name__)


def validate_uuid(map, key):
    try:
        # Verify UUID is valid, then convert to canonical string representation
        # to avoiid DB errors.
        map[key] = canonical_uuid_string(map[key])
    except ValueError:
        msg = '{} is not a valid UUID'.format(map[key])
        raise falcon.HTTPBadRequest('Bad request', msg)


def validate_uuids(req, params):
    id_keys = ['token_id', 'auth_id', 'host_id', 'user_id', 'project-id',
               'instance-id']
    if req.method in ('POST', 'PUT'):
        for key in id_keys:
            if key in req.body:
                validate_uuid(req.body, key)
    for key in id_keys:
        if key in params:
            validate_uuid(params, key)


def validate(req, resp, resource, params):
    if req.content_length:
        # Store the body since we cannot read the stream again later
        req.body = json.load(req.stream)
    elif req.method in ('POST', 'PUT'):
        raise falcon.HTTPBadRequest('The POST/PUT request is missing a body.')
    validate_uuids(req, params)


class Logger(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def process_resource(self, req, resp, resource, params):
        self.logger.debug('Received request {0} {1} with headers {2}'
                          .format(req.method, req.relative_uri, req.headers))

    def process_response(self, req, resp, resource, params):
        self.logger.debug(
            'Request {0} {1} with body {2} produced response '
            'with status {3} location {4} and body {5}'.format(
                req.method, req.relative_uri,
                req.body if hasattr(req, 'body') else 'None',
                resp.status, resp.location, resp.body))


def _authAsDict(auth):
    return {
        'auth_id': auth.auth_id,
        'name': auth.name,
        'user_pub_key': auth.user_pub_key,
        'host_pub_key': auth.host_pub_key,
    }

class Authorities(object):
    @falcon.before(validate)
    def on_post(self, req, resp):
        id = req.body['auth_id']
        try:
            db.createAuthority(
                self.session,
                id,
                getProjectNameForID(id)
            )
        except KeyError as e:
            raise falcon.HTTPBadRequest(str(e))
        resp.status = falcon.HTTP_201
        resp.location = '/authorities/{}'.format(id)

    @falcon.before(validate)
    def on_get(self, req, resp):
        body = {'CAs': [_authAsDict(auth)
                        for auth in db.getAuthorities(self.session)]}
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK


class Authority(object):
    @falcon.before(validate)
    def on_get(self, req, resp, auth_id):
        auth = db.getAuthority(self.session, auth_id)
        if auth is None:
            resp.status = falcon.HTTP_NOT_FOUND
            return
        resp.body = json.dumps(_authAsDict(auth))
        resp.status = falcon.HTTP_OK

def _userCertAsDict(cert):
    return {
        'user_id': cert.user_id,
        'user_name': cert.user_name,
        'principals': cert.principals,
        'fingerprint': cert.fingerprint,
        'auth_id': cert.auth_id,
        'cert': cert.cert.strip('\n'),
        'revoked': cert.revoked,
        'serial': cert.serial,
        'created_at': datetime_to_string(cert.created_at),
        'expires_at': datetime_to_string(cert.expires_at),
    }

class UserCerts(object):
    @falcon.before(validate)
    def on_post(self, req, resp):
        # TODO(pino): validation
        id = req.body['user_id']
        try:
            user_cert = db.createUserCert(
                self.session,
                id,
                getUserNameForID(id),
                req.body['auth_id'],
                req.body['pub_key']
            )
        except KeyError as e:
            raise falcon.HTTPBadRequest(str(e))
        resp.status = falcon.HTTP_201
        resp.location = '/usercerts/{}/{}'.format(id, user_cert.fingerprint)
        resp.body = json.dumps(_userCertAsDict(user_cert))

    @falcon.before(validate)
    def on_get(self, req, resp):
        body = {'certs': [_userCertAsDict(cert)
                          for cert in db.getUserCerts(self.session)]}
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK


class UserCert(object):
    @falcon.before(validate)
    def on_get(self, req, resp, serial):
        user = db.getUserCertBySerial(self.session, serial)
        if user is None:
            resp.status = falcon.HTTP_NOT_FOUND
            return
        resp.body = json.dumps(_userCertAsDict(user))
        resp.status = falcon.HTTP_OK


def _hostAsDict(host):
    return {
        'id': host.id,
        'name': host.name,
        'pat_bastions': host.pat_bastions,
        'srv_url': host.srv_url,
    }


class Hosts(object):
    @falcon.before(validate)
    def on_get(self, req, resp):
        body = {'hosts': [_hostAsDict(host)
                          for host in db.getHosts(self.session)]}
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK


class Host(object):
    @falcon.before(validate)
    def on_get(self, req, resp, host_id):
        host = db.getHost(self.session, host_id)
        if host is None:
            resp.status = falcon.HTTP_NOT_FOUND
            return
        resp.body = json.dumps(_hostAsDict(host))
        resp.status = falcon.HTTP_OK


def _hostCertAsDict(cert):
    return {
        'host_id': cert.host_id,
        'fingerprint': cert.fingerprint,
        'auth_id': cert.auth_id,
        'cert': cert.cert.strip('\n'),
        'hostname': cert.hostname,
        'created_at': datetime_to_string(cert.created_at),
        'expires_at': datetime_to_string(cert.expires_at),
    }


class HostCerts(object):
    @falcon.before(validate)
    def on_post(self, req, resp):
        # Note that we could have found the host_id using the token_id.
        # But requiring the host_id makes it a bit harder to steal the token.
        try:
            cert = db.createHostCert(
                self.session,
                req.body['token_id'],
                req.body['host_id'],
                req.body['pub_key']
            )
        except KeyError as e:
            raise falcon.HTTPBadRequest(str(e))
        resp.body = json.dumps(_hostCertAsDict(cert))
        resp.status = falcon.HTTP_200
        resp.location = '/hostcerts/' + cert.host_id + '/' + cert.fingerprint

    @falcon.before(validate)
    def on_get(self, req, resp):
        body = {'certs': [_hostCertAsDict(cert)
                          for cert in db.getHostCerts(self.session)]}
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK


class HostCert(object):
    @falcon.before(validate)
    def on_get(self, req, resp, host_id, fingerprint):
        cert = db.getHostCert(self.session, host_id, fingerprint)
        if cert is None:
            resp.status = falcon.HTTP_NOT_FOUND
            return
        resp.body = json.dumps(_hostCertAsDict(cert))
        resp.status = falcon.HTTP_OK


class Tokens(object):
    @falcon.before(validate)
    def on_post(self, req, resp):
        try:
            token = db.createToken(
                self.session,
                req.body['host_id'],
                req.body['auth_id'],
                req.body['hostname']
            )
        except KeyError as e:
            raise falcon.HTTPBadRequest(str(e))
        resp.status = falcon.HTTP_201
        resp.location = '/hosttokens/' + token.token_id


class NovaVendorData(object):
    @falcon.before(validate)
    def on_post(self, req, resp):
        # An example of the data nova sends to vendordata services:
        # {
        #     "hostname": "foo",
        #     "image-id": "75a74383-f276-4774-8074-8c4e3ff2ca64",
        #     "instance-id": "2ae914e9-f5ab-44ce-b2a2-dcf8373d899d",
        #     "metadata": {},
        #     "project-id": "039d104b7a5c4631b4ba6524d0b9e981",
        #     "user-data": null
        # }
        instance_id = req.body['instance-id']
        hostname = req.body['hostname']
        project_id = req.body['project-id']
        try:
            token = db.createToken(
                self.session,
                instance_id,
                project_id,
                hostname,
            )
        except KeyError as e:
            raise falcon.HTTPBadRequest(str(e))
        auth = db.getAuthority(self.session, project_id)
        if auth is None:
            resp.status = falcon.HTTP_NOT_FOUND
            return
        roles = getProjectRoleNames(req.body['project-id'])
        vendordata = {
            'token': token.token_id,
            'auth_pub_key_user': auth.user_pub_key,
            'root_principals': '', #keep in case we want to use it later
            'users': ','.join(roles),
            'sudoers': ','.join([r for r in roles if "admin" in r]),
            'ssh_port': CONF.tatu.ssh_port,
        }
        resp.body = json.dumps(vendordata)
        resp.location = '/hosttokens/' + token.token_id
        resp.status = falcon.HTTP_201

        host = db.getHost(self.session, instance_id)
        if host is None:
            # TODO(pino): make the whole workflow fault-tolerant
            # TODO(pino): make this configurable per project or subnet
            pat_bastions = ''
            srv_url = ''
            if CONF.tatu.use_pat_bastions:
                ip_port_tuples = create_pat_entries(self.session, instance_id)
                srv_url = add_srv_records(hostname, auth.name, ip_port_tuples)
                pat_bastions = ip_port_tuples_to_string(ip_port_tuples)
            # else, e.g. call LBaaS API

            db.createHost(session=self.session,
                          id=instance_id,
                          name=hostname,
                          pat_bastions=pat_bastions,
                          srv_url=srv_url,
                         )


class RevokedUserKeys(object):
    @falcon.before(validate)
    def on_get(self, req, resp, auth_id):
        body = {
            'auth_id': auth_id,
            'encoding': 'base64',
            'revoked_keys_data': db.getRevokedKeysBase64(self.session, auth_id)
        }
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK

    @falcon.before(validate)
    def on_post(self, req, resp, auth_id):
        db.revokeUserKey(
            self.session,
            auth_id,
            serial=req.body.get('serial', None),
        )
        resp.status = falcon.HTTP_OK
        resp.body = json.dumps({})


class PATs(object):
    @falcon.before(validate)
    def on_get(self, req, resp):
        items = []
        if CONF.tatu.use_pat_bastions:
            for p in getAllPats():
                items.append({
                    'ip': str(p.ip_address),
                    'chassis': p.chassis.id,
                    'lport': p.lport.id,
                })
        body = {'pats': items}
        resp.body = json.dumps(body)
        resp.status = falcon.HTTP_OK
