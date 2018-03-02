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

from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import sys
import time
import uuid

from tatu import ks_utils
from tatu.config import CONF
from tatu.config import KEYSTONE as ks
from tatu.config import NOVA as nova
from tatu.db import models as db
from tatu.dns import delete_srv_records
from tatu.utils import canonical_uuid_string

if CONF.tatu.use_pat_bastions:
    from tatu.pat import deletePatEntries, string_to_ip_port_tuples

LOG = logging.getLogger(__name__)


class NotificationEndpoint(object):
    filter_rule = oslo_messaging.NotificationFilter(
        publisher_id='^identity.*|^compute.*',
        event_type='^identity.project.(created|deleted)|'
                   '^identity.user.deleted|'
                   '^identity.role_assignment.deleted|'
                   '^compute.instance.delete.end')
    #TODO(pino): what about user removal from a project? (rather than deletion)

    def __init__(self, engine):
        self.Session = scoped_session(sessionmaker(engine))

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        LOG.debug('notification:')
        LOG.debug(jsonutils.dumps(payload, indent=4))

        LOG.debug("publisher: %s, event: %s, metadata: %s", publisher_id,
                  event_type, metadata)

        se = self.Session()
        if event_type == 'identity.project.created':
            proj_id = canonical_uuid_string(payload.get('resource_info'))
            name = ks_utils.getProjectNameForID(proj_id)
            _createAuthority(self.Session, proj_id, name)
        elif event_type == 'identity.project.deleted':
            # Assume all the users and instances must have been removed.
            proj_id = canonical_uuid_string(payload.get('resource_info'))
            _deleteAuthority(self.Session,
                             db.getAuthority(self.Session(), proj_id))
        elif event_type ==  'identity.role_assignment.deleted':
            users = []
            if 'user' in payload:
                users = [payload['user']]
            else:
                users = ks_utils.getUserIdsByGroupId(payload['group'])
            # TODO: look for domain if project isn't available
            proj_id = payload['project']
            for user_id in users:
                roles = ks_utils.getProjectRoleNamesForUser(proj_id, user_id)
                try:
                    se = self.Session()
                    db.revokeUserCertsForRoleChange(se, user_id, proj_id, roles)
                except Exception as e:
                    LOG.error(
                        "Failed to revoke user {} certificates in project {} "
                        "after role {} was removed, due to exception {}"
                            .format(user_id, proj_id, payload['role'], e))
                    import traceback; traceback.print_exc()
                    se.rollback()
                    self.Session.remove()
        elif event_type ==  'identity.user.deleted':
            user_id = payload.get('resource_info')
            LOG.debug("User with ID {} deleted "
                      "in Keystone".format(user_id))
            try:
                db.revokeUserCerts(se, user_id)
                # TODO(pino): also prevent generating new certs for this user?
            except Exception as e:
                LOG.error(
                    "Failed to revoke all certs for deleted user with ID {} "
                    "due to exception {}".format(user_id, e))
                se.rollback()
                self.Session.remove()
        elif event_type == 'compute.instance.delete.end':
            instance_id = canonical_uuid_string(payload.get('instance_id'))
            host = db.getHost(se, instance_id)
            if host is not None:
                _deleteHost(self.Session, host)
            # TODO(Pino): record the deletion to prevent new certs generation?
            pass
        else:
            LOG.error("Unknown update.")


def _createAuthority(session_factory, auth_id, name):
    se = session_factory()
    if db.getAuthority(se, auth_id) is not None:
        return
    try:
        db.createAuthority(se, auth_id, name)
        LOG.info("Created CA for project {} with ID {}".format(name, auth_id))
    except Exception as e:
        LOG.error(
            "Failed to create CA for project {} with ID {} "
            "due to exception {}".format(name, auth_id, e))
        se.rollback()
        session_factory.remove()


def _deleteAuthority(session_factory, auth):
    se = session_factory()
    try:
        LOG.info(
            "Deleting CA for project {} with ID {} - not in Keystone"
                .format(auth.name, auth.auth_id))
        db.deleteAuthority(se, auth.auth_id)
    except Exception as e:
        LOG.error(
            "Failed to delete Tatu CA for project {} with ID {} "
            "due to exception {}".format(proj.name, auth_id, e))
        se.rollback()
        session_factory.remove()


def _deleteHost(session_factory, host):
    LOG.debug("Clean up DNS and PAT for deleted instance {} with ID {}"
              .format(host.name, host.id))
    if CONF.tatu.use_pat_bastions:
        delete_srv_records(host.srv_url)
        deletePatEntries(string_to_ip_port_tuples(host.pat_bastions))
    se = session_factory()
    try:
        LOG.info(
            "Deleting Host {} with ID {} - not in Keystone"
                .format(host.name, host.id))
        se.delete(host)
        se.commit()
    except:
        LOG.error(
            "Failed to delete Host {} with ID {} - not in Keystone"
                .format(host.name, host.id))
        se.rollback()
        session_factory.remove()


def sync(engine):
    session_factory = scoped_session(sessionmaker(engine))
    ks_project_ids = set()
    LOG.info("Add CAs for new projects in Keystone.")
    for proj in ks.projects.list():
        ks_project_ids.add(canonical_uuid_string(proj.id))
        _createAuthority(session_factory,
                         canonical_uuid_string(proj.id),
                         proj.name)

    # Iterate through all CAs in Tatu. Delete any that don't have a
    # corresponding project in Keystone.
    LOG.info("Remove CAs for projects that were deleted from Keystone.")
    for auth in db.getAuthorities(session_factory()):
        if auth.auth_id not in ks_project_ids:
            _deleteAuthority(session_factory, auth)

    ks_user_ids = set()
    for user in ks.users.list():
        ks_user_ids.add(user.id)

    LOG.info("Revoke user certificates if user was deleted or lost a role.")
    for cert in db.getUserCerts(session_factory()):
        if cert.revoked: continue
        se = session_factory()

        try:
            # Invalidate the cert if the user was removed from Keystone
            if cert.user_id not in ks_user_ids:
                db.revokeUserCert(se, cert)
                continue

            # Invalidate the cert if it has any principals that aren't current
            roles = ks_utils.getProjectRoleNamesForUser(cert.auth_id,
                                                        cert.user_id)
            old_roles = cert.principals.split(",")
            removed_roles = set(old_roles) - set(roles)
            if len(removed_roles) > 0:
                LOG.info("Revoking certificate with serial {} for user {}"
                         " because roles/principals {} were removed."
                    .format(cert.serial, cert.user_name, removed_roles))
                db.revokeUserCert(se, cert)

        except:
            LOG.error(
            "Failed to delete certificate with serial {} for user {}"
                .format(cert.serial, cert.user_id))
            se.rollback()
            session_factory.remove()

    # Iterate through all the instance IDs in Tatu. Clean up DNS and PAT for
    # any that no longer exist in Nova.
    LOG.info("Delete DNS and PAT resources of any server that was deleted.")
    instance_ids = set()
    for instance in nova.servers.list(search_opts={'all_tenants': True}):
        instance_ids.add(canonical_uuid_string(instance.id))
    for host in db.getHosts(session_factory()):
        if host.id not in instance_ids:
            _deleteHost(session_factory, host)


def main():
    transport = oslo_messaging.get_notification_transport(CONF)
    targets = [oslo_messaging.Target(topic='tatu_notifications')]
    storage_engine = create_engine(CONF.tatu.sqlalchemy_engine)

    endpoints = [NotificationEndpoint(storage_engine)]

    server = oslo_messaging.get_notification_listener(transport,
                                                      targets,
                                                      endpoints,
                                                      executor='threading')

    # At startup, do an overall sync.
    sync(storage_engine)

    LOG.info("Starting notification watcher daemon")
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        LOG.info("Stopping, be patient")
        server.stop()
        server.wait()


if __name__ == "__main__":
    sys.exit(main())
