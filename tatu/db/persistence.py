import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from tatu.db.models import Base


def get_url():
    return os.getenv("DATABASE_URL", "sqlite:///development.db")
    #return os.getenv("DATABASE_URL", "sqlite:///:memory:")

class SQLAlchemySessionManager:
    """
    Create a scoped session for every request and close it when the request
    ends.
    """

    def __init__(self):
        self.engine = create_engine(get_url())
        Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(self.engine))

    def process_resource(self, req, resp, resource, params):
        resource.session = self.Session()

    def process_response(self, req, resp, resource, req_succeeded):
        if hasattr(resource, 'session'):
            if not req_succeeded:
                resource.session.rollback()
            self.Session.remove()
