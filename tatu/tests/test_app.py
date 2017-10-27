# coding=utf-8
import json
import falcon
from falcon import testing
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

def user_request(auth=auth_id, user_id=None):
  if user_id is None:
    user_id = str(uuid.uuid4())
  user_key = RSA.generate(2048)
  pub_key = user_key.publickey().exportKey('OpenSSH') 
  return {
    'user_id': user_id,
    'auth_id': auth,
    'pub_key': pub_key
  }  

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_user(client, db):
  body = user_request()
  response = client.simulate_post(
    '/usercerts',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location = response.headers['location'].split('/')
  assert location[1] == 'usercerts'
  assert location[2] == body['user_id']
  assert location[3] == sshpubkeys.SSHKey(body['pub_key']).hash()

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_user_bad_auth(client, db):
  body = user_request(str(uuid.uuid4()))
  response = client.simulate_post(
    '/usercerts',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_NOT_FOUND

def token_request(auth=auth_id, instance_id=None):
  if instance_id is None:
    instance_id = str(uuid.uuid4())
  return {
    'instance_id': instance_id,
    'auth_id': auth,
    'hostname': 'testname.local'
  }  

def host_request(token_id, instance_id=None):
  if instance_id is None:
    instance_id = str(uuid.uuid4())
  host_key = RSA.generate(2048)
  pub_key = str(host_key.publickey().exportKey('OpenSSH'))
  return {
    'token_id': token_id,
    'instance_id': instance_id,
    'pub_key': pub_key
  }

@pytest.mark.dependency(depends=['test_post_authority'])
def test_host_cert_workflow(client, db):
  token = token_request()
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  host = host_request(location_path[-1], token['instance_id'])
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location = response.headers['location'].split('/')
  assert location[1] == 'hostcerts'
  assert location[2] == host['instance_id']
  assert location[3] == sshpubkeys.SSHKey(host['pub_key']).hash()

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_token_bad_auth(client, db):
  token = token_request(str(uuid.uuid4()))
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_NOT_FOUND

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_host_with_bogus_token(client, db):
  token = token_request(str(uuid.uuid4()))
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_NOT_FOUND

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_host_with_wrong_instance_id(client, db):
  token = token_request()
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  # Use the token with a different instance_id
  host = host_request(location_path[-1], str(uuid.uuid4()))
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_host_with_used_token(client, db):
  token = token_request()
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  # First, use the token to sign a host public key
  host = host_request(location_path[-1], token['instance_id'])
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location = response.headers['location'].split('/')
  assert location[1] == 'hostcerts'
  assert location[2] == host['instance_id']
  assert location[3] == sshpubkeys.SSHKey(host['pub_key']).hash()
  # Now try using the token a sceond time, same instance_id, different pub key
  host = host_request(location_path[-1], token['instance_id'])
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_FORBIDDEN 
