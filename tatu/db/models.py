import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
import sshpubkeys
import uuid
import subprocess
import os

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class Authority(Base):
  __tablename__ = 'authorities'

  id = sa.Column(sa.String(36), primary_key=True)
  user_pubkey = sa.Column(sa.Text)
  user_privkey = sa.Column(sa.Text)
  host_pubkey = sa.Column(sa.Text)
  host_privkey = sa.Column(sa.Text)

def createAuthority(session, id, user_pub, user_priv, host_pub, host_priv):
  with session:
    auth = Authority(id=id,
                     user_pubkey=user_pub,
                     user_privkey=user_priv,
                     host_pubkey=host_pub,
                     host_privkey=host_priv)
    session.add(auth)
    session.commit()
    return auth

class UserCert(Base):
  __tablename__ = 'user_certs'

  user_id = sa.Column(sa.String(36), primary_key=True)
  auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.id'))
  fingerprint = sa.Column(sa.String(36), primary_key=True)
  privkey = sa.Column(sa.Text)
  pubkey = sa.Column(sa.Text)
  cert = sa.Column(sa.Text)

def generateCert(auth_key, entity_key, host_name=None):
    # Temporarily write the authority private key and entity public key to /tmp
    ca_file = '/tmp'.join(uuid.uuid4().hex)
    pub_prefix = uuid.uuid4().hex
    pub_file = ''.join('/tmp/', pub_prefix, '.pub')
    with open(ca_file, "w") as text_file:
      text_file.write(auth_key)
    with open(pub_file, "w") as text_file:
      text_file.write(entity_key)
    # Call keygen
    if host_name is None:
      subprocess.call(['ssh-keygen', '-P "pino"', '-s', ca_file, '-I testID', '-V -1d:+365d', '-n "myRoot,yourRoot"', pub_file], shell=True)
    else:
      subprocess.call(['ssh-keygen', '-P "pino"', '-s', ca_file, '-I testID', '-V -1d:+365d', '-n', host_name, '-h', pub_file], shell=True)
    # Read the contents of the certificate file
    cert_file = ''.join('/tmp/', pub_prefix, '-cert.pub')
    cert = ''
    with open(cert_file, 'r') as text_file:
      cert = text_file.read()
    # Delete temporary files
    for file in [ca_file, pub_file, cert_file]:
      os.remove(file)
    return cert

def createUserCert(session, id, auth_id, pub, priv):
  with session:
    user = User(id=id,
                auth_id=auth_id,
                pubkey=pub,
                privkey=priv)
    # Generate the fingerprint from the public key
    user.fingerprint = sshpubkeys.SSHKey(pub).hash()
    # Retrieve the authority's private key and generate the certificate
    auth = session.query(Authority).get(auth_id)
    if auth is None:
      raise falcon.HTTPNotFound("Unrecognized certificate authority")
    user.cert = generateCert(auth.user_privkey, pub)
    session.add(user)
    session.commit()
    return user

class Token(Base):
  __tablename__ = 'tokens'

  id = sa.Column(sa.String(36), primary_key=True, 
                 default=generate_uuid)
  hostname = sa.Column(sa.String(36))
  instance_id = sa.Column(sa.String(36))
  auth_id = sa.Column(sa.String(36), ForeignKey('authorities.id'))
  used = sa.Column(sa.Boolean)
  date_used = sa.Column(sa.Date)
  fingerprint_used = sa.Column(sa.String(36), optional)

def createToken(session, instance_id, auth_id, hostname):
  with session:
    # Validate the certificate authority
    auth = session.query(Authority).get(auth_id)
    if auth is None:
      raise falcon.HTTPNotFound("Unrecognized certificate authority")
    token = Token(instance_id=instance_id,
                  auth_id=auth_id,
                  hostname=hostname,
                  used=false)
    session.add(token)
    session.commit()
    return token

class HostCert(Base):
  __tablename__ = 'host_certs'

  id = sa.Column(sa.String(36), primary_key=True)
  fingerprint = sa.Column(sa.String(36), primary_key=True)
  token_id = sa.Column(sa.String(36), sa.ForeignKey('tokens.id'))
  pubkey = sa.Column(sa.Text)
  cert = sa.Column(sa.Text)

def createHostCert(session, token_id, pub):
  with session:
    token =  session.query(Token).get(token_id)
    if token is None:
      raise falcon.HTTPNotFound("Unrecognized token")
    if token.used:
      raise falcon.HTTPForbidden(description='The presented token was previously used')
    auth = session.query(Authority).get(token.auth_id)
    if auth is None:
      raise falcon.HTTPNotFound("Unrecognized certificate authority")
    host = HostCert(id=token.instance_id,
                    fingerprint=sshpubkeys.SSHKey(pub).hash()
                    token_id=token_id,
                    pubkey=pub,
                    cert=generateCert(auth.host_privkey, pub))
    session.add(host)
    # Update the token
    token.used = true
    token.date_used = now
    token.fingerprint_used = host.fingerprint
    session.add(token)
    session.commit()
    return host
