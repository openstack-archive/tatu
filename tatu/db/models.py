from datetime import datetime
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import IntegrityError
import falcon
import sshpubkeys
import uuid
import os
from tatu.utils import generateCert
from Crypto.PublicKey import RSA

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class Authority(Base):
  __tablename__ = 'authorities'

  auth_id = sa.Column(sa.String(36), primary_key=True)
  user_key = sa.Column(sa.Text)
  host_key = sa.Column(sa.Text)

def getAuthority(session, auth_id):
  return session.query(Authority).get(auth_id)

def createAuthority(session, auth_id):
  auth = Authority(auth_id=auth_id,
                   user_key=RSA.generate(2048).exportKey('PEM'),
                   host_key=RSA.generate(2048).exportKey('PEM'))
  session.add(auth)
  try:
    session.commit()
  except IntegrityError:
    raise falcon.HTTPConflict("This certificate authority already exists.")
  return auth

class UserCert(Base):
  __tablename__ = 'user_certs'

  user_id = sa.Column(sa.String(36), primary_key=True)
  fingerprint = sa.Column(sa.String(36), primary_key=True)
  auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
  cert = sa.Column(sa.Text)

def getUserCert(session, user_id, fingerprint):
  return session.query(UserCert).get([user_id, fingerprint])

def createUserCert(session, user_id, auth_id, pub):
    # Retrieve the authority's private key and generate the certificate
    auth = getAuthority(session, auth_id)
    if auth is None:
      raise falcon.HTTPNotFound()
    fingerprint = sshpubkeys.SSHKey(pub).hash()
    certRecord = session.query(UserCert).get([user_id, fingerprint])
    if certRecord is not None:
      raise falcon.HTTPConflict('This public key is already signed.')
    cert = generateCert(auth.user_key, pub)
    if cert is None:
      raise falcon.HTTPInternalServerError("Failed to generate the certificate")
    user = UserCert(
      user_id=user_id,
      fingerprint=fingerprint,
      auth_id=auth_id,
      cert=cert
    )
    session.add(user)
    session.commit()
    return user

class Token(Base):
  __tablename__ = 'tokens'

  token_id = sa.Column(sa.String(36), primary_key=True, 
                 default=generate_uuid)
  auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
  host_id = sa.Column(sa.String(36))
  hostname = sa.Column(sa.String(36))
  used = sa.Column(sa.Boolean, default=False)
  date_used = sa.Column(sa.DateTime, default=datetime.min)
  fingerprint_used = sa.Column(sa.String(36))

def createToken(session, host_id, auth_id, hostname):
    # Validate the certificate authority
    auth = getAuthority(session, auth_id)
    if auth is None:
      raise falcon.HTTPNotFound()
    token = Token(host_id=host_id,
                  auth_id=auth_id,
                  hostname=hostname)
    session.add(token)
    session.commit()
    return token

class HostCert(Base):
  __tablename__ = 'host_certs'

  host_id = sa.Column(sa.String(36), primary_key=True)
  fingerprint = sa.Column(sa.String(36), primary_key=True)
  auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
  token_id = sa.Column(sa.String(36), sa.ForeignKey('tokens.token_id'))
  pubkey = sa.Column(sa.Text)
  cert = sa.Column(sa.Text)
  hostname = sa.Column(sa.String(36))

def getHostCert(session, host_id, fingerprint):
  return session.query(HostCert).get([host_id, fingerprint])

def createHostCert(session, token_id, host_id, pub):
    token =  session.query(Token).get(token_id)
    if token is None:
      raise falcon.HTTPNotFound()
    if token.used:
      raise falcon.HTTPForbidden(description='The presented token was previously used')
    if token.host_id != host_id:
      raise falcon.HTTPForbidden(description='The token is not valid for this instance ID')
    auth = getAuthority(session, token.auth_id)
    if auth is None:
      raise falcon.HTTPNotFound()
    fingerprint = sshpubkeys.SSHKey(pub).hash()
    certRecord = session.query(HostCert).get([host_id, fingerprint])
    if certRecord is not None:
      raise falcon.HTTPConflict('This public key is already signed.')
    cert = generateCert(auth.host_key, pub, token.hostname)
    if cert == '':
      raise falcon.HTTPInternalServerError("Failed to generate the certificate")
    host = HostCert(host_id=host_id,
                    fingerprint=fingerprint,
                    auth_id=token.auth_id,
                    token_id=token_id,
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
