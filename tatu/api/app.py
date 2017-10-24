import falcon
import models
from tatu.db.persistence import SQLAlchemySessionManager

def create_app(sa):
  api = falcon.API(middleware=[sa])
  api.add_route('/authorities', models.Authorities())
  api.add_route('/authorities/{uuid}', models.Authority())
  api.add_route('/users/{uuid}/certs', models.UserCerts())
  api.add_route('/users/{uuid}/certs/{fingerprint}', models.UserCert())
  api.add_route('/hosts/{uuid}/certs', models.HostCerts())
  api.add_route('/hosts/{uuid}/certs/{fingerprint}', models.HostCert())
  api.add_route('/host_cert_tokens', models.Token())
  return api


def get_app():
  return create_app(SQLAlchemySessionManager())
