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

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from tatu import config
from tatu.db.models import Base

class SQLAlchemySessionManager(object):

    def __init__(self):
        self.engine = create_engine(config.CONF.tatu.sqlalchemy_engine)
        Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(self.engine))

    def process_resource(self, req, resp, resource, params):
        # Create a scoped session for every request
        resource.session = self.Session()

    def process_response(self, req, resp, resource, req_succeeded):
        if hasattr(resource, 'session'):
            if not req_succeeded:
                resource.session.rollback()
            # Close the scoped session when the request ends
            self.Session.remove()
