# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystoneauth1.identity import v3 as ks_v3
from keystoneauth1 import session as ks_session
from keystoneclient.v3 import client as ks_client_v3
from oslo_log import log as logging
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from tatu import config # sets up all required config
from tatu.db.models import Base, createAuthority, getAuthority
from tatu.db.persistence import get_url
import uuid

LOG = logging.getLogger(__name__)

auth = ks_v3.Password(auth_url='http://localhost/identity/v3',
                      user_id='fab01a1f2a7749b78a53dffe441a1879',
                      password='pinot',
                      project_id='2e6c998ad16f4045821304470a57d160')
keystone = ks_client_v3.Client(session=ks_session.Session(auth=auth))
projects = keystone.projects.list()

engine = create_engine(get_url())
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker(engine))

LOG.debug("Creating CAs for {} Keystone projects.".format(len(projects)))
for proj in projects:
    se = Session()
    try:
        auth_id = str(uuid.UUID(proj.id, version=4))
        if getAuthority(se, auth_id) is None:
            createAuthority(se, auth_id)
            LOG.info("Created CA for project {} with ID {}".format(proj.name,
                                                                   auth_id))
        else:
            LOG.info("CA already exists for project {}".format(proj.name))
    except Exception as e:
        LOG.error(
            "Failed to create Tatu CA for project {} with ID {} "
            "due to exception {}".format(proj.name, auth_id, e))
        se.rollback()
        Session.remove()
