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

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import sys
import time
import uuid

from tatu.db.models import createAuthority
from tatu.db.persistence import get_url

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
DOMAIN = 'tatu'


class NotificationEndpoint(object):
    filter_rule = oslo_messaging.NotificationFilter(
        publisher_id='^identity.*',
        event_type='^identity.project.created')

    def __init__(self):
        self.engine = create_engine(get_url())
        # Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(self.engine))

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        LOG.debug('notification:')
        LOG.debug(jsonutils.dumps(payload, indent=4))

        LOG.debug("publisher: %s, event: %s, metadata: %s", publisher_id,
                  event_type, metadata)

        if event_type == 'identity.project.created':
            proj_id = payload.get('resource_info')
            LOG.debug("New project created {}".format(proj_id))
            se = self.Session()
            try:
                auth_id = str(uuid.UUID(proj_id, version=4))
                createAuthority(se, auth_id)
            except Exception as e:
                LOG.error(
                    "Failed to create Tatu CA for new project with ID {} "
                    "due to exception {}".format(proj_id, e))
                se.rollback()
                self.Session.remove()
        else:
            LOG.error("Status update or unknown")


def main():
    logging.register_options(CONF)
    log_levels = logging.get_default_log_levels() + \
        ['tatu=DEBUG', '__main__=DEBUG']
    logging.set_defaults(default_log_levels=log_levels)
    logging.setup(CONF, DOMAIN)

    transport = oslo_messaging.get_notification_transport(CONF)
    targets = [oslo_messaging.Target(topic='notifications')]
    endpoints = [NotificationEndpoint()]

    server = oslo_messaging.get_notification_listener(transport,
                                                      targets,
                                                      endpoints,
                                                      executor='threading')

    LOG.info("Starting")
    LOG.debug("Test debug log statement")
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
