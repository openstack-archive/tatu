import falcon
import models
from tatu.db.persistence import SQLAlchemySessionManager

def create_app(sa):
  api = falcon.API(middleware=[sa])
  api.add_route('/authorities', models.Authorities())
  api.add_route('/authorities/{ca_id}', models.Authority())
  api.add_route('/usercerts', models.UserCerts())
  api.add_route('/usercerts/{user_id}/{fingerprint}', models.UserCert())
  api.add_route('/hostcerts', models.HostCerts())
  api.add_route('/hostcerts/{host_id}/{fingerprint}', models.HostCert())
  api.add_route('/hosttokens', models.Token())
  return api


def get_app():
  return create_app(SQLAlchemySessionManager())
