from datetime import datetime
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
import falcon
import sshpubkeys
import uuid
import os
from tatu.utils import generateCert

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class Authority(Base):
  __tablename__ = 'authorities'

  auth_id = sa.Column(sa.String(36), primary_key=True)
  user_pubkey = sa.Column(sa.Text)
  user_privkey = sa.Column(sa.Text)
  host_pubkey = sa.Column(sa.Text)
  host_privkey = sa.Column(sa.Text)

def createAuthority(session, auth_id, user_pub, user_priv, host_pub, host_priv):
    auth = Authority(auth_id=auth_id,
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
  fingerprint = sa.Column(sa.String(36), primary_key=True)
  auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
  pubkey = sa.Column(sa.Text)
  cert = sa.Column(sa.Text)

def createUserCert(session, user_id, auth_id, pub):
    user = UserCert(
      user_id=user_id,
      auth_id=auth_id,
      pubkey=pub,
    )
    # Generate the fingerprint from the public key
    user.fingerprint = sshpubkeys.SSHKey(pub).hash()
    # Retrieve the authority's private key and generate the certificate
    auth = session.query(Authority).get(auth_id)
    if auth is None:
      raise falcon.HTTPNotFound()
    user.cert = generateCert(auth.user_privkey, pub)
    if user.cert == '':
      raise falcon.HTTPInternalServerError("Failed to generate the certificate")
    session.add(user)
    session.commit()
    return user

class Token(Base):
  __tablename__ = 'tokens'

  token_id = sa.Column(sa.String(36), primary_key=True, 
                 default=generate_uuid)
  auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
  instance_id = sa.Column(sa.String(36))
  hostname = sa.Column(sa.String(36))
  used = sa.Column(sa.Boolean, default=False)
  date_used = sa.Column(sa.DateTime, default=datetime.min)
  fingerprint_used = sa.Column(sa.String(36))

def createToken(session, instance_id, auth_id, hostname):
    # Validate the certificate authority
    auth = session.query(Authority).get(auth_id)
    if auth is None:
      raise falcon.HTTPNotFound()
    token = Token(instance_id=instance_id,
                  auth_id=auth_id,
                  hostname=hostname)
    session.add(token)
    session.commit()
    return token

class HostCert(Base):
  __tablename__ = 'host_certs'

  instance_id = sa.Column(sa.String(36), primary_key=True)
  fingerprint = sa.Column(sa.String(36), primary_key=True)
  token_id = sa.Column(sa.String(36), sa.ForeignKey('tokens.token_id'))
  pubkey = sa.Column(sa.Text)
  cert = sa.Column(sa.Text)
  hostname = sa.Column(sa.String(36))

def createHostCert(session, token_id, instance_id, pub):
    token =  session.query(Token).get(token_id)
    if token is None:
      raise falcon.HTTPNotFound()
    if token.used:
      raise falcon.HTTPForbidden(description='The presented token was previously used')
    if token.instance_id != instance_id:
      raise falcon.HTTPForbidden(description='The token is not valid for this instance ID')
    auth = session.query(Authority).get(token.auth_id)
    if auth is None:
      raise falcon.HTTPNotFound()
    cert = generateCert(auth.host_privkey, pub, token.hostname)
    if cert == '':
      raise falcon.HTTPInternalServerError("Failed to generate the certificate")
    host = HostCert(instance_id=instance_id,
                    fingerprint=sshpubkeys.SSHKey(pub).hash(),
                    token_id=token_id,
                    pubkey=pub,
                    cert=cert,
                    hostname=token.hostname)
    session.add(host)
    # Update the token
    token.used = True
    token.date_used = datetime.utcnow()
    token.fingerprint_used = host.fingerprint
    session.add(token)
    session.commit()
    return host
