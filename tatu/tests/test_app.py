# coding=utf-8
import json
import falcon
from falcon import testing
import pytest
import uuid
from tatu.api.app import create_app
from tatu.db.persistence import SQLAlchemySessionManager
from tatu.db.models import Authority
from tatu.utils import random_uuid
from Crypto.PublicKey import RSA
import sshpubkeys
import time

@pytest.fixture
def db():
  return SQLAlchemySessionManager()

@pytest.fixture
def client(db):
  api = create_app(db)
  return testing.TestClient(api)

token_id = ''

host_id = random_uuid()
host_key = RSA.generate(2048)
host_pub_key = host_key.publickey().exportKey('OpenSSH')
host_fingerprint = sshpubkeys.SSHKey(host_pub_key).hash_md5()

user_id = random_uuid()
user_key = RSA.generate(2048)
user_pub_key = user_key.publickey().exportKey('OpenSSH')
user_fingerprint = sshpubkeys.SSHKey(user_pub_key).hash_md5()

auth_id = random_uuid()
auth_user_pub_key = None

@pytest.mark.dependency()
def test_post_authority(client, auth_id=auth_id):
  body = {
    'auth_id': auth_id,
  }
  response = client.simulate_post(
    '/authorities',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_CREATED
  assert response.headers['location'] == '/authorities/' + auth_id

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_authority_duplicate(client):
  body = {
    'auth_id': auth_id,
  }
  response = client.simulate_post(
    '/authorities',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_CONFLICT

def test_post_no_body(client):
  for path in ['/authorities', '/usercerts', '/hosttokens',
               '/hostcerts', '/novavendordata']:
    response = client.simulate_post(path)
    assert response.status == falcon.HTTP_BAD_REQUEST

def test_post_empty_body(client):
  bodystr = json.dumps({})
  for path in ['/authorities', '/usercerts', '/hosttokens',
               '/hostcerts', '/novavendordata']:
    response = client.simulate_post(path, body=bodystr)
    assert response.status == falcon.HTTP_BAD_REQUEST

def test_post_authority_bad_uuid(client):
  body = {
    'auth_id': 'foobar',
  }
  response = client.simulate_post(
    '/authorities',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_BAD_REQUEST

@pytest.mark.dependency(depends=['test_post_authority'])
def test_get_authority(client):
  response = client.simulate_get('/authorities/' + auth_id)
  assert response.status == falcon.HTTP_OK
  body = json.loads(response.content)
  assert 'auth_id' in body
  assert 'user_key.pub' in body
  global auth_user_pub_key
  auth_user_pub_key = body['user_key.pub']
  assert 'host_key.pub' in body
  assert 'user_key' not in body
  assert 'host_key' not in body

def test_get_authority_doesnt_exist(client):
  response = client.simulate_get('/authorities/' + random_uuid())
  assert response.status == falcon.HTTP_NOT_FOUND

def test_get_authority_with_bad_uuid(client):
  response = client.simulate_get('/authorities/foobar')
  assert response.status == falcon.HTTP_BAD_REQUEST

def user_request(auth=auth_id, user_id=user_id, pub_key=user_pub_key):
  return {
    'user_id': user_id,
    'auth_id': auth,
    'key.pub': pub_key
  }

def test_post_user_bad_uuid(client):
  for key in ['user_id', 'auth_id']:
    body = user_request()
    body[key] = 'foobar'
    response = client.simulate_post(
      '/usercerts',
      body=json.dumps(body)
    )
    assert response.status == falcon.HTTP_BAD_REQUEST

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_user(client):
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
  assert location[3] == sshpubkeys.SSHKey(body['key.pub']).hash_md5()

@pytest.mark.dependency(depends=['test_post_user'])
def test_get_user(client):
  response = client.simulate_get('/usercerts/' + user_id + '/' + user_fingerprint)
  assert response.status == falcon.HTTP_OK
  body = json.loads(response.content)
  assert 'user_id' in body
  assert 'fingerprint' in body
  assert 'auth_id' in body
  assert 'key-cert.pub' in body
  assert body['auth_id'] == auth_id

def test_get_user_doesnt_exist(client):
  response = client.simulate_get('/usercerts/' + random_uuid() + '/' + user_fingerprint)
  assert response.status == falcon.HTTP_NOT_FOUND

def test_get_user_with_bad_uuid(client):
  response = client.simulate_get('/usercerts/foobar/' + user_fingerprint)
  assert response.status == falcon.HTTP_BAD_REQUEST

@pytest.mark.dependency(depends=['test_post_user'])
def test_post_second_cert_same_user(client):
  key = RSA.generate(2048)
  pub_key = key.publickey().exportKey('OpenSSH')
  body = user_request(pub_key=pub_key)
  response = client.simulate_post(
    '/usercerts',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location = response.headers['location'].split('/')
  assert location[1] == 'usercerts'
  assert location[2] == user_id
  assert location[3] == sshpubkeys.SSHKey(pub_key).hash_md5()

def test_post_user_unknown_auth(client):
  body = user_request(auth=random_uuid())
  response = client.simulate_post(
    '/usercerts',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_NOT_FOUND

@pytest.mark.dependency(depends=['test_post_user'])
def test_post_same_user_same_key_fails(client):
  # Show that using the same user ID and public key fails.
  body = user_request()
  response = client.simulate_post(
    '/usercerts',
    body=json.dumps(body)
  )
  assert response.status == falcon.HTTP_CONFLICT

def token_request(auth=auth_id, host=host_id):
  return {
    'host_id': host,
    'auth_id': auth,
    'hostname': 'testname.local'
  }

def host_request(token, host=host_id, pub_key=host_pub_key):
  return {
    'token_id': token,
    'host_id': host,
    'key.pub': pub_key
  }

def vendordata_request(auth, host):
  return {
    'instance-id': host,
    'project-id': auth,
    'hostname': 'mytest.testing'
  }

def test_post_vendordata_bad_uuid(client):
  for key in ['instance-id', 'project-id']:
    body = vendordata_request(auth_id, host_id)
    body[key] = 'foobar'
    response = client.simulate_post(
      '/novavendordata',
      body=json.dumps(body)
    )
    assert response.status == falcon.HTTP_BAD_REQUEST

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_novavendordata(client):
  req = vendordata_request(auth_id, random_uuid())
  response = client.simulate_post(
    '/novavendordata',
    body=json.dumps(req)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  vendordata = json.loads(response.content)
  assert 'token' in vendordata
  assert vendordata['token'] == location_path[-1]
  assert 'auth_pub_key_user' in vendordata
  assert vendordata['auth_pub_key_user'] == auth_user_pub_key
  assert 'principals' in vendordata
  assert vendordata['principals'] == 'admin'

def test_post_token_bad_uuid(client):
  for key in ['auth_id', 'host_id']:
    body = token_request()
    body[key] = 'foobar'
    response = client.simulate_post(
      '/hosttokens',
      body=json.dumps(body)
    )
    assert response.status == falcon.HTTP_BAD_REQUEST

def test_post_host_bad_uuid(client):
  for key in ['token_id', 'host_id']:
    body = host_request(random_uuid())
    body[key] = 'foobar'
    response = client.simulate_post(
      '/hosttokens',
      body=json.dumps(body)
    )
    assert response.status == falcon.HTTP_BAD_REQUEST

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_token_and_host(client):
  token = token_request()
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  # Store the token ID for other tests
  global token_id
  token_id = location_path[-1]
  # Verify that it's a valid UUID
  uuid.UUID(token_id, version=4)
  host = host_request(token_id)
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location = response.headers['location'].split('/')
  assert location[1] == 'hostcerts'
  assert location[2] == host_id
  assert location[3] == host_fingerprint

def test_stress_post_token_and_host(client):
  my_auth_id = random_uuid()
  test_post_authority(client, my_auth_id)
  # Generate a single RSA key pair and reuse it - it takes a few seconds.
  key = RSA.generate(2048)
  pub_key = key.publickey().exportKey('OpenSSH')
  fingerprint = sshpubkeys.SSHKey(pub_key).hash_md5()
  # Should do about 15 iterations/second, so only do 4 seconds worth.
  start = time.time()
  for i in range(60):
    hid = random_uuid()
    token = token_request(auth=my_auth_id, host=hid)
    response = client.simulate_post(
      '/hosttokens',
      body=json.dumps(token)
    )
    assert response.status == falcon.HTTP_CREATED
    assert 'location' in response.headers
    location_path = response.headers['location'].split('/')
    assert location_path[1] == 'hosttokens'
    token_id = location_path[-1]
    # Verify that it's a valid UUID
    uuid.UUID(token_id, version=4)
    host = host_request(token_id, host=hid, pub_key=pub_key)
    response = client.simulate_post(
      '/hostcerts',
      body=json.dumps(host)
    )
    assert response.status == falcon.HTTP_CREATED
    assert 'location' in response.headers
    location = response.headers['location'].split('/')
    assert location[1] == 'hostcerts'
    assert location[2] == hid
    assert location[3] == fingerprint
  assert time.time() - start < 5

@pytest.mark.dependency(depends=['test_post_token_and_host'])
def test_post_token_same_host_id(client):
  # Posting with the same host ID should return the same token
  token = token_request()
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  # The token id should be the same as that from the previous test.
  assert token_id == location_path[-1]

@pytest.mark.dependency(depends=['test_post_token_and_host'])
def test_get_host(client):
  response = client.simulate_get('/hostcerts/' + host_id + '/' + host_fingerprint)
  assert response.status == falcon.HTTP_OK
  body = json.loads(response.content)
  assert 'host_id' in body
  assert 'fingerprint' in body
  assert 'auth_id' in body
  assert 'key-cert.pub' in body
  assert body['host_id'] == host_id
  assert body['fingerprint'] == host_fingerprint
  assert body['auth_id'] == auth_id

def test_get_host_doesnt_exist(client):
  response = client.simulate_get('/hostcerts/' + random_uuid() + '/' + host_fingerprint)
  assert response.status == falcon.HTTP_NOT_FOUND

def test_get_host_with_bad_uuid(client):
  response = client.simulate_get('/hostcerts/foobar/' + host_fingerprint)
  assert response.status == falcon.HTTP_BAD_REQUEST

def test_post_token_unknown_auth(client):
  token = token_request(auth=random_uuid())
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_NOT_FOUND

@pytest.mark.dependency(depends=['test_post_authority'])
def test_post_host_with_bogus_token(client):
  host = host_request(random_uuid(), random_uuid())
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_NOT_FOUND

@pytest.mark.dependency(depends=['test_post_token_and_host'])
def test_post_host_with_wrong_host_id(client):
  # Get a new token for the same host_id as the base test.
  token = token_request(host=random_uuid())
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  # Use the token with a different host_id than it was created for.
  # Use a different public key to avoid other error conditions.
  key = RSA.generate(2048)
  pub_key = key.publickey().exportKey('OpenSSH')
  host = host_request(location_path[-1], random_uuid(), pub_key)
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_CONFLICT

@pytest.mark.dependency(depends=['test_post_token_and_host'])
def test_post_host_different_public_key_fails(client):
  # Use the same token compared to the test this depends on.
  # Show that using the same host ID and different public key fails.
  token = token_request()
  response = client.simulate_post(
    '/hosttokens',
    body=json.dumps(token)
  )
  assert response.status == falcon.HTTP_CREATED
  assert 'location' in response.headers
  location_path = response.headers['location'].split('/')
  assert location_path[1] == 'hosttokens'
  key = RSA.generate(2048)
  pub_key = key.publickey().exportKey('OpenSSH')
  host = host_request(location_path[-1], pub_key=pub_key)
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_CONFLICT

@pytest.mark.dependency(depends=['test_post_token_and_host'])
def test_post_host_with_used_token(client):
  # Re-use the token from the test this depends on.
  # Use the same host_id and different public key to avoid other errors.
  key = RSA.generate(2048)
  pub_key = key.publickey().exportKey('OpenSSH')
  host = host_request(token_id, host_id, pub_key)
  response = client.simulate_post(
    '/hostcerts',
    body=json.dumps(host)
  )
  assert response.status == falcon.HTTP_CONFLICT
