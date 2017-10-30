import falcon
import json
from tatu.db import models as db
from Crypto.PublicKey import RSA


class Authorities(object):

  def on_post(self, req, resp):
    body = None
    if req.content_length:
      body = json.load(req.stream)
    db.createAuthority(
      self.session,
      body['auth_id'],
    )
    resp.status = falcon.HTTP_201
    resp.location = '/authorities/' + body['auth_id']

class Authority(object):

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

  def on_post(self, req, resp):
    body = None
    if req.content_length:
      body = json.load(req.stream)
    # TODO: validation
    user = db.createUserCert(
      self.session,
      body['user_id'],
      body['auth_id'],
      body['key.pub']
    )
    resp.status = falcon.HTTP_201
    resp.location = '/usercerts/' + user.user_id + '/' + user.fingerprint

class UserCert(object):

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

class HostCerts(object):

  def on_post(self, req, resp):
    body = None
    if req.content_length:
      body = json.load(req.stream)
    host = db.createHostCert(
      self.session,
      body['token_id'],
      body['host_id'],
      body['key.pub']
    )
    resp.status = falcon.HTTP_201
    resp.location = '/hostcerts/' + host.host_id + '/' + host.fingerprint

class HostCert(object):

  def on_get(self, req, resp, host_id, fingerprint):
    host = db.getHostCert(self.session, host_id, fingerprint)
    if host is None:
      resp.status = falcon.HTTP_NOT_FOUND
      return
    body = {
      'host_id': host.host_id,
      'fingerprint': host.fingerprint,
      'auth_id': host.auth_id,
      'key-cert.pub': host.pubkey,
    }
    resp.body = json.dumps(body)
    resp.status = falcon.HTTP_OK

class Tokens(object):

  def on_post(self, req, resp):
    body = None
    if req.content_length:
      body = json.load(req.stream)
    token = db.createToken(
      self.session,
      body['host_id'],
      body['auth_id'],
      body['hostname']
    )
    resp.status = falcon.HTTP_201
    resp.location = '/hosttokens/' + token.token_id

class NovaVendorData(object):

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
    body = None
    if req.content_length:
      body = json.load(req.stream)
    token = db.createToken(
      self.session,
      body['instance-id'],
      body['project-id'],
      body['hostname']
    )
    auth = db.getAuthority(self.session, body['project-id'])
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
