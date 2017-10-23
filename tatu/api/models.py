import falcon


class Authorities(object):

  def on_post(self, req, resp):
    resp.status = falcon.HTTP_400

class Authority(object):

  def on_get(self, req, resp):
    resp.status = falcon.HTTP_400

class UserCerts(object):

  def on_get(self, req, resp):
    resp.status = falcon.HTTP_400

class UserCert(object):

  def on_get(self, req, resp):
    resp.status = falcon.HTTP_400

  def on_post(self, req, resp):
    resp.status = falcon.HTTP_400

class HostCerts(object):

  def on_get(self, req, resp):
    resp.status = falcon.HTTP_400

class HostCert(object):

  def on_get(self, req, resp):
    resp.status = falcon.HTTP_400

  def on_post(self, req, resp):
    resp.status = falcon.HTTP_400

