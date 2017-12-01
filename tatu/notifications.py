from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import sys
from tatu.db.models import Base, createAuthority
from tatu.db.persistence import get_url
import time
import uuid

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
DOMAIN = 'tatu'

class NotificationEndpoint(object):

    filter_rule = oslo_messaging.NotificationFilter(
        publisher_id='^identity.*',
        event_type='^identity.project.created')

    def __init__(self):
        self.engine = create_engine(get_url())
        #Base.metadata.create_all(self.engine)
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
                LOG.error("Failed to create Tatu CA for new project with ID {} due to exception {}".format(proj_id, e))
                se.rollback()
                self.Session.remove()
        else:
            LOG.error("Status update or unknown")

def main():
    logging.register_options(CONF)
    extra_log_level_defaults = ['tatu=DEBUG', '__main__=DEBUG']
    logging.set_defaults(
        default_log_levels=logging.get_default_log_levels() +
        extra_log_level_defaults)
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
