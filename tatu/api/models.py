import falcon
import json
from tatu.db import models as db


class Authorities(object):

  def on_post(self, req, resp):
    body = None
    if req.content_length:
      body = json.load(req.stream)
    db.createAuthority(
      self.session,
      body['auth_id'],
      body['user_pubkey'],
      body['user_privkey'],
      body['host_pubkey'],
      body['host_privkey']
    )
    resp.status = falcon.HTTP_201
    resp.location = '/authorities/' + body['auth_id']

class Authority(object):

  def on_get(self, req, resp, ca_id):
    resp.status = falcon.HTTP_400

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
      body['pub_key']
    )
    resp.status = falcon.HTTP_201
    resp.location = '/usercerts/' + user.user_id + '/' + user.fingerprint

class UserCert(object):

  def on_get(self, req, resp, user_id, fingerprint):
    resp.status = falcon.HTTP_400

class HostCerts(object):

  def on_post(self, req, resp):
    body = None
    if req.content_length:
      body = json.load(req.stream)
    host = db.createHostCert(
      self.session,
      body['token_id'],
      body['instance_id'],
      body['pub_key']
    )
    resp.status = falcon.HTTP_201
    resp.location = '/hostcerts/' + host.instance_id + '/' + host.fingerprint

class HostCert(object):

  def on_get(self, req, resp, host_id, fingerprint):
    resp.status = falcon.HTTP_400

class Token(object):

  def on_post(self, req, resp):
    body = None
    if req.content_length:
      body = json.load(req.stream)
    token = db.createToken(
      self.session,
      body['instance_id'],
      body['auth_id'],
      body['hostname']
    )
    resp.status = falcon.HTTP_201
    resp.location = '/hosttokens/' + token.token_id
