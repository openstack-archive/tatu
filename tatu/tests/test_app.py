# coding=utf-8
import json
import falcon
from falcon import testing
import msgpack
import pytest
import uuid
from tatu.api.app import create_app
from tatu.db.persistence import SQLAlchemySessionManager
from tatu.db.models import Authority
from Crypto.PublicKey import RSA

@pytest.fixture
def db():
    return SQLAlchemySessionManager()

@pytest.fixture
def client(db):
    api = create_app(db)
    return testing.TestClient(api)

def test_post_authority(client, db):
  auth_id = str(uuid.uuid4())
  user_ca = RSA.generate(2048)
  host_ca = RSA.generate(2048)
  body = {
    'íd': auth_id,
    'user_privkey': user_ca.exportKey('PEM'),
    'user_pubkey': user_ca.publickey().exportKey('OpenSSH'),
    'host_privkey': host_ca.exportKey('PEM'),
    'host_pubkey': host_ca.publickey().exportKey('OpenSSH')
  }  
  response = client.simulate_post(
    '/authorities',
    body=json.dumps(body),
  )
  #with db.Session() as session:
  session = db.Session()
  auth = session.query(Authority).get(auth_id)
  assert auth is not None

