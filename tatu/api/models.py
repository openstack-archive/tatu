import falcon
import json
import logging
import uuid
from tatu.db import models as db
from Crypto.PublicKey import RSA

def validate_uuid(map, key):
  try:
    # Verify it's a valid UUID, then convert to canonical string representation
    # to avoiid DB errors.
    map[key] = str(uuid.UUID(map[key], version=4))
  except ValueError:
    msg = '{} is not a valid UUID'.format(map[key])
    raise falcon.HTTPBadRequest('Bad request', msg)

def validate_uuids(req, params):
  id_keys = ['token_id', 'auth_id', 'host_id', 'user_id', 'project-id', 'instance-id']
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
    self.logger = logging.getLogger('gunicorn.error')

  def process_resource(self, req, resp, resource, params):
    self.logger.debug('Received request {0} {1}'.format(req.method, req.relative_uri))

  def process_response(self, req, resp, resource, params):
    self.logger.debug(
      'Request {0} {1} with body {2} produced response '
      'with status {3} location {4} and body {5}'.format(
        req.method, req.relative_uri,
        req.body if hasattr(req, 'body') else 'None',
        resp.status, resp.location, resp.body))

class Authorities(object):

  @falcon.before(validate)
  def on_post(self, req, resp):
    try:
      db.createAuthority(
        self.session,
        req.body['auth_id'],
      )
    except KeyError as e:
      raise falcon.HTTPBadRequest(str(e))
    resp.status = falcon.HTTP_201
    resp.location = '/authorities/' + req.body['auth_id']

class Authority(object):

  @falcon.before(validate)
  def on_get(self, req, resp, auth_id):
    auth = db.getAuthority(self.session, auth_id)
    if auth is None:
      resp.status = falcon.HTTP_NOT_FOUND
      return
    user_key = RSA.importKey(auth.user_key)
    user_pub_key = user_key.publickey().exportKey('OpenSSH')
    host_key = RSA.importKey(auth.host_key)
    host_pub_key = host_key.publickey().exportKey('OpenSSH')
    body = {
      'auth_id': auth_id,
      'user_key.pub': user_pub_key,
      'host_key.pub': host_pub_key
    }
    resp.body = json.dumps(body)
    resp.status = falcon.HTTP_OK

class UserCerts(object):

  @falcon.before(validate)
  def on_post(self, req, resp):
    # TODO: validation
    try:
      user = db.createUserCert(
        self.session,
        req.body['user_id'],
        req.body['auth_id'],
        req.body['key.pub']
      )
    except KeyError as e:
      raise falcon.HTTPBadRequest(str(e))
    resp.status = falcon.HTTP_201
    resp.location = '/usercerts/' + user.user_id + '/' + user.fingerprint

class UserCert(object):

  @falcon.before(validate)
  def on_get(self, req, resp, user_id, fingerprint):
    user = db.getUserCert(self.session, user_id, fingerprint)
    if user is None:
      resp.status = falcon.HTTP_NOT_FOUND
      return
    body = {
      'user_id': user.user_id,
      'fingerprint': user.fingerprint,
      'auth_id': user.auth_id,
      'key-cert.pub': user.cert
    }
    resp.body = json.dumps(body)
    resp.status = falcon.HTTP_OK

def hostToJson(host):
  return json.dumps({
    'host_id': host.host_id,
    'fingerprint': host.fingerprint,
    'auth_id': host.auth_id,
    'key-cert.pub': host.cert,
  })

class HostCerts(object):

  @falcon.before(validate)
  def on_post(self, req, resp):
    # Note that we could have found the host_id using the token_id.
    # But requiring the host_id makes it a little harder to steal the token.
    try:
      host = db.createHostCert(
        self.session,
        req.body['token_id'],
        req.body['host_id'],
        req.body['key.pub']
      )
    except KeyError as e:
      raise falcon.HTTPBadRequest(str(e))
    resp.body = hostToJson(host)
    resp.status = falcon.HTTP_201
    resp.location = '/hostcerts/' + host.host_id + '/' + host.fingerprint

class HostCert(object):

  @falcon.before(validate)
  def on_get(self, req, resp, host_id, fingerprint):
    host = db.getHostCert(self.session, host_id, fingerprint)
    if host is None:
      resp.status = falcon.HTTP_NOT_FOUND
      return
    resp.body = hostToJson(host)
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
    try:
      token = db.createToken(
        self.session,
        req.body['instance-id'],
        req.body['project-id'],
        req.body['hostname']
      )
    except KeyError as e:
      raise falcon.HTTPBadRequest(str(e))
    auth = db.getAuthority(self.session, req.body['project-id'])
    if auth is None:
      resp.status = falcon.HTTP_NOT_FOUND
      return
    key = RSA.importKey(auth.user_key)
    pub_key = key.publickey().exportKey('OpenSSH')
    vendordata = {
      'token': token.token_id,
      'auth_pub_key_user': pub_key,
      'principals': 'admin'
    }
    resp.body = json.dumps(vendordata)
    resp.location = '/hosttokens/' + token.token_id
    resp.status = falcon.HTTP_201
