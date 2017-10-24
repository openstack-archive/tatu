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
import sshpubkeys

@pytest.fixture
def db():
    return SQLAlchemySessionManager()

@pytest.fixture
def client(db):
    api = create_app(db)
    return testing.TestClient(api)

auth_id = str(uuid.uuid4())

@pytest.mark.dependency()
def test_post_authority(client, db):
  user_ca = RSA.generate(2048)
  host_ca = RSA.generate(2048)
  body = {
    'auth_id': auth_id,
    'user_privkey': user_ca.exportKey('PEM'),
    'user_pubkey': user_ca.publickey().exportKey('OpenSSH'),
    'host_privkey': host_ca.exportKey('PEM'),
    'host_pubkey': host_ca.publickey().exportKey('OpenSSH')
  }  
  response = client.simulate_post(
    '/authorities',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_CREATED
  assert response.headers['location'] == '/authorities/' + auth_id
  #with db.Session() as session:
  session = db.Session()
  auth = session.query(Authority).get(auth_id)
  assert auth is not None

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_user(client, db):
  user_id = str(uuid.uuid4())
  user_key = RSA.generate(2048)
  pub_key = user_key.publickey().exportKey('OpenSSH') 
  body = {
    'user_id': user_id,
    'auth_id': auth_id,
    'priv_key': user_key.exportKey('PEM'),
    'pub_key': pub_key
  }  
  response = client.simulate_post(
    '/user_certs',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location = response.headers['location'].split('/')
  assert location[1] == 'users'
  assert location[2] == user_id
  assert location[3] == 'certs'
  assert location[4] == sshpubkeys.SSHKey(pub_key).hash()


@pytest.mark.dependency(depends=['test_post_authority'])
@pytest.mark.skip(reason="not working yet")
def test_host_cert_workflow(client, db):
  instance_id = str(uuid.uuid4())
  token = {
    'instance_id': instance_id,
    'auth_id': auth_id,
    'hostname': 'testname.local'
  }  
  response = client.simulate_post(
    '/host_cert_tokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'host_cert_tokens'
  host_key = RSA.generate(2048)
  pub_key = str(host_key.publickey().exportKey('OpenSSH'))
  host = {
    'token_id': location_path[-1],
    'pub_key': pub_key
  }
  response = client.simulate_post(
    '/host_certs',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  cert = json.loads(response.body)
