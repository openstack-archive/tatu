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
from datetime import datetime, timedelta
import falcon
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
import sshpubkeys

from tatu.castellano import get_secret, store_secret
from tatu.ks_utils import getProjectRoleNamesForUser
from tatu.utils import canonical_uuid_string, generateCert, revokedKeysBase64, random_uuid

Base = declarative_base()


class Authority(Base):
    __tablename__ = 'authorities'

    auth_id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(36))
    user_key = sa.Column(sa.Text)
    host_key = sa.Column(sa.Text)
    user_pub_key = sa.Column(sa.Text)
    host_pub_key = sa.Column(sa.Text)


def getAuthority(session, auth_id):
    return session.query(Authority).get(auth_id)


def getAuthorities(session):
    return session.query(Authority)


def getAuthHostKey(auth):
    return


def _newPubPrivKeyPair():
    k = RSA.generate(2048)
    return k.publickey().exportKey('OpenSSH'), k.exportKey('PEM')


def createAuthority(session, auth_id, name):
    user_pub_key, user_key = _newPubPrivKeyPair()
    user_secret_id = store_secret(user_key)
    host_pub_key, host_key = _newPubPrivKeyPair()
    host_secret_id = store_secret(host_key)
    auth = Authority(
        auth_id=auth_id,
        name=name,
        user_key=user_secret_id,
        host_key=host_secret_id,
        user_pub_key = user_pub_key,
        host_pub_key = host_pub_key,
    )
    session.add(auth)
    try:
        session.commit()
    except IntegrityError:
        raise falcon.HTTPConflict("This certificate authority already exists.")
    return auth


def deleteAuthority(session, auth_id):
    session.delete(getAuthority(session, auth_id))
    session.commit()


class UserCert(Base):
    __tablename__ = 'user_certs'

    serial = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    user_name = sa.Column(sa.String(20))
    principals = sa.Column(sa.String(100))
    created_at = sa.Column(sa.DateTime, default=lambda: datetime.utcnow())
    expires_at = sa.Column(sa.DateTime, default=lambda: datetime.utcnow()
                                                        + timedelta(days=365))
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


def createUserCert(session, user_id, user_name, auth_id, pub):
    # Retrieve the authority's private key and generate the certificate
    auth = getAuthority(session, auth_id)
    if auth is None:
        raise falcon.HTTPNotFound(
            description='No Authority found with that ID')
    fingerprint = sshpubkeys.SSHKey(pub).hash_md5()
    certRecord = getUserCert(session, user_id, fingerprint)
    if certRecord is not None:
        return certRecord
    principals = getProjectRoleNamesForUser(auth_id, user_id)
    user = UserCert(
        user_id=user_id,
        user_name=user_name,
        principals=','.join(principals),
        fingerprint=fingerprint,
        auth_id=auth_id,
    )
    session.add(user)
    session.flush()
    user.cert = generateCert(
        get_secret(auth.user_key), pub, user=True, principal_list=principals,
        serial=user.serial, days_valid=365, identity=user_name
    )
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
    return revokedKeysBase64(auth.user_pub_key, serials)


def revokeUserCert(session, cert):
    cert.revoked = True
    session.add(cert)
    session.add(db.RevokedKey(cert.auth_id, serial=cert.serial))
    session.commit()


def revokeUserCerts(session, user_id):
    # TODO(Pino): send an SQL statement instead of retrieving and iterating?
    for u in session.query(UserCert).filter(UserCert.user_id == user_id):
        u.revoked = True
        session.add(u)
        session.add(RevokedKey(u.auth_id, serial=u.serial))
    session.commit()


def revokeUserCertsInProject(session, user_id, project_id):
    # TODO(Pino): send an SQL statement instead of retrieving and iterating?
    for u in session.query(UserCert).filter(UserCert.user_id == user_id).filter(UserCert.auth_id == project_id):
        u.revoked = True
        session.add(u)
        session.add(RevokedKey(u.auth_id, serial=u.serial))
    session.commit()


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


class Host(Base):
    __tablename__ = 'hosts'

    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(36))
    pat_bastions = sa.Column(sa.String(70)) # max 3 ip:port pairs
    srv_url = sa.Column(sa.String(100)) # _ssh._tcp.<host>.<project>.<zone>


def createHost(session, id, name, pat_bastions, srv_url):
    host = Host(id=id, name=name, pat_bastions=pat_bastions, srv_url=srv_url)
    session.add(host)
    try:
        session.commit()
    except IntegrityError:
        raise falcon.HTTPConflict("Failed to create SSH host record for {}."
                                  .format(name))
    return host


def getHost(session, id):
    return session.query(Host).get(id)


def getHosts(session):
    return session.query(Host)


def deleteHost(session, host):
    session.delete(host)
    session.commit()


class HostCert(Base):
    __tablename__ = 'host_certs'

    host_id = sa.Column(sa.String(36), primary_key=True)
    fingerprint = sa.Column(sa.String(60), primary_key=True)
    created_at = sa.Column(sa.DateTime, default=lambda: datetime.utcnow())
    expires_at = sa.Column(sa.DateTime, default=lambda: datetime.utcnow()
                                                        + timedelta(days=365))
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
    cert = generateCert(get_secret(auth.host_key), pub, user=False,
                        days_valid=365, identity=token.hostname)
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
