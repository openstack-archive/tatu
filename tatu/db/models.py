#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from Crypto.PublicKey import RSA
from datetime import datetime
import falcon
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
import sshpubkeys

from tatu.castellano import get_secret, store_secret
from tatu.utils import generateCert, revokedKeysBase64, random_uuid

Base = declarative_base()


class Authority(Base):
    __tablename__ = 'authorities'

    auth_id = sa.Column(sa.String(36), primary_key=True)
    user_key = sa.Column(sa.Text)
    host_key = sa.Column(sa.Text)


def getAuthority(session, auth_id):
    return session.query(Authority).get(auth_id)


def getAuthorities(session):
    return session.query(Authority)


def getAuthUserKey(auth):
    return get_secret(auth.user_key)


def getAuthHostKey(auth):
    return get_secret(auth.host_key)


def createAuthority(session, auth_id):
    user_key = RSA.generate(2048).exportKey('PEM')
    user_secret_id = store_secret(user_key)
    host_key = RSA.generate(2048).exportKey('PEM')
    host_secret_id = store_secret(host_key)
    auth = Authority(auth_id=auth_id,
                     user_key=user_secret_id,
                     host_key=host_secret_id)
    session.add(auth)
    try:
        session.commit()
    except IntegrityError:
        raise falcon.HTTPConflict("This certificate authority already exists.")
    return auth


class UserCert(Base):
    __tablename__ = 'user_certs'

    serial = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = sa.Column(sa.String(36))
    fingerprint = sa.Column(sa.String(60))
    auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
    cert = sa.Column(sa.Text)
    revoked = sa.Column(sa.Boolean, default=False)

sa.Index('idx_user_finger', UserCert.user_id, UserCert.fingerprint, unique=True)


def getUserCertBySerial(session, serial):
    try:
        return session.query(UserCert).get(serial)
    except Exception:
        return None


def getUserCert(session, user_id, fingerprint):
    return session.query(UserCert).filter(
            UserCert.user_id == user_id).filter(
                    UserCert.fingerprint == fingerprint).one_or_none()


def getUserCerts(session):
    return session.query(UserCert)


def createUserCert(session, user_id, auth_id, pub):
    # Retrieve the authority's private key and generate the certificate
    auth = getAuthority(session, auth_id)
    if auth is None:
        raise falcon.HTTPNotFound(
            description='No Authority found with that ID')
    fingerprint = sshpubkeys.SSHKey(pub).hash_md5()
    certRecord = getUserCert(session, user_id, fingerprint)
    if certRecord is not None:
        return certRecord
    user = UserCert(
        user_id=user_id,
        fingerprint=fingerprint,
        auth_id=auth_id,
    )
    session.add(user)
    session.flush()
    user.cert = generateCert(getAuthUserKey(auth), pub, user=True,
                        principals='admin,root', serial=user.serial)
    if user.cert is None:
        raise falcon.HTTPInternalServerError(
            "Failed to generate the certificate")
    
    session.commit()
    return user


class RevokedKey(Base):
    __tablename__ = 'revoked_keys'

    auth_id = sa.Column(sa.String(36), primary_key=True)
    serial = sa.Column(sa.Integer, sa.ForeignKey("user_certs.serial"),
                       primary_key=True)


def getRevokedKeysBase64(session, auth_id):
    auth = getAuthority(session, auth_id)
    if auth is None:
        raise falcon.HTTPNotFound(
            description='No Authority found with that ID')
    serials = [k.serial for k in session.query(RevokedKey).filter(
        RevokedKey.auth_id == auth_id)]
    user_key = RSA.importKey(getAuthUserKey(auth))
    user_pub_key = user_key.publickey().exportKey('OpenSSH')
    return revokedKeysBase64(user_pub_key, serials)


def revokeUserKey(session, auth_id, serial=None, key_id=None, cert=None):
    ser = None
    userCert = None
    if serial is not None:
        try:
            userCert = getUserCertBySerial(session, serial)
        except Exception:
            pass
        if userCert is None:
            raise falcon.HTTPBadRequest(
                "Can't find the certificate for serial # {}".format(serial))
        if userCert.auth_id != auth_id:
            raise falcon.HTTPBadRequest(
                "Incorrect CA ID for serial # {}".format(serial))
        ser = serial
    elif key_id is not None:
        # TODO(pino): look up the UserCert by key id and get the serial number
        pass
    elif cert is not None:
        # TODO(pino): Decode the cert, validate against UserCert and get serial
        pass

    if ser is None or userCert is None:
        raise falcon.HTTPBadRequest("Cannot identify which Cert to revoke.")
    if userCert.revoked:
        raise falcon.HTTPBadRequest("Certificate was already revoked.")

    userCert.revoked = True
    session.add(userCert)
    session.add(RevokedKey(auth_id=auth_id, serial=ser))
    session.commit()

class Token(Base):
    __tablename__ = 'tokens'

    token_id = sa.Column(sa.String(36), primary_key=True,
                         default=random_uuid)
    auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
    host_id = sa.Column(sa.String(36), index=True, unique=True)
    hostname = sa.Column(sa.String(36))
    used = sa.Column(sa.Boolean, default=False)
    date_used = sa.Column(sa.DateTime, default=datetime.min)
    fingerprint_used = sa.Column(sa.String(60))


def createToken(session, host_id, auth_id, hostname):
    # Validate the certificate authority
    auth = getAuthority(session, auth_id)
    if auth is None:
        raise falcon.HTTPNotFound(
            description='No Authority found with that ID')
    # Check whether a token was already created for this host_id
    try:
        token = session.query(Token).filter(Token.host_id == host_id).one()
        if token is not None:
            return token
    except Exception:
        pass

    token = Token(host_id=host_id,
                  auth_id=auth_id,
                  hostname=hostname)
    session.add(token)
    session.commit()
    return token


class HostCert(Base):
    __tablename__ = 'host_certs'

    host_id = sa.Column(sa.String(36), primary_key=True)
    fingerprint = sa.Column(sa.String(60), primary_key=True)
    auth_id = sa.Column(sa.String(36), sa.ForeignKey('authorities.auth_id'))
    token_id = sa.Column(sa.String(36), sa.ForeignKey('tokens.token_id'))
    pubkey = sa.Column(sa.Text)
    cert = sa.Column(sa.Text)
    hostname = sa.Column(sa.String(36))


def getHostCert(session, host_id, fingerprint):
    return session.query(HostCert).get([host_id, fingerprint])


def getHostCerts(session):
    return session.query(HostCert)


def createHostCert(session, token_id, host_id, pub):
    token = session.query(Token).get(token_id)
    if token is None:
        raise falcon.HTTPNotFound(description='No Token found with that ID')
    if token.host_id != host_id:
        raise falcon.HTTPConflict(
            description='The token is not valid for this instance ID')
    fingerprint = sshpubkeys.SSHKey(pub).hash_md5()

    if token.used:
        if token.fingerprint_used != fingerprint:
            raise falcon.HTTPConflict(
                description='Token already signed a different public key')
        # The token was already used for same host and pub key. Return record.
        host = session.query(HostCert).get([host_id, fingerprint])
        if host is None:
            raise falcon.HTTPInternalServerError(
                description='Token already used, but Host record not found.')
        if host.token_id == token_id:
            return host
        raise falcon.HTTPConflict(
            description='The presented token was previously used')

    auth = getAuthority(session, token.auth_id)
    if auth is None:
        raise falcon.HTTPNotFound(
            description='No Authority found with that ID')
    certRecord = session.query(HostCert).get([host_id, fingerprint])
    if certRecord is not None:
        raise falcon.HTTPConflict('This public key is already signed.')
    cert = generateCert(getAuthHostKey(auth), pub, user=False)
    if cert == '':
        raise falcon.HTTPInternalServerError(
            "Failed to generate the certificate")
    host = HostCert(host_id=host_id,
                    fingerprint=fingerprint,
                    auth_id=token.auth_id,
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


class L4PortReservation(Base):
    __tablename__ = 'port_reservation'
    ip_address = sa.Column(sa.String(36), primary_key=True)
    # For now, just auto-increment the l4 port. Later, we'll reuse them.
    l4_port = sa.Column(sa.Integer, primary_key=True, autoincrement=True)


def reserve_l4_port(session, ip):
    rsv = L4PortReservation(ip_address=str(ip))
    session.add(rsv)
    session.commit()
    return rsv.l4_port
