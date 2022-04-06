import sqlalchemy
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from app.config.conf import DatabaseConfig

Base = declarative_base()


class AlertEvidence(Base):
    """
    Database ORM to store Alert-Evidence info
    identifier = alert_id + evidence_sha256
    """

    __tablename__ = DatabaseConfig.TABLE_NAME
    id = Column(Integer, primary_key=True)
    identifier = Column(String, unique=True)


class Database:
    """
    Class to handle database operations
    """

    def __init__(self, log):
        """
        Initialize Database instance and create database table if not exists
        :param log: logger instance
        :return: void
        """
        self.log = log
        self.create_table()

    @staticmethod
    def check_table_exists():
        """
        Check table exists with using DatabaseConfig
        :return: void
        """
        return sqlalchemy.inspect(DatabaseConfig.engine).has_table(DatabaseConfig.TABLE_NAME)

    def create_table(self):
        """
        Create table if not exists in the database
        :return: void
        """
        if not self.check_table_exists():
            Base.metadata.create_all(DatabaseConfig.engine)
            self.log.info("Creating %s table" % DatabaseConfig.TABLE_NAME)

    def check_alert_evidence_exists(self, identifier):
        """
        Check given identifier exists in the table
        :param identifier: alert_id + evidence_sha256 data to check duplicates
        :exception: when database connection error occurs
        :return Bool: existence status of identifier
        """
        try:
            exists = DatabaseConfig.session.query(AlertEvidence.identifier) \
                         .filter(AlertEvidence.identifier == identifier) \
                         .first() is not None
            return exists
        except Exception as err:
            self.log.error("Database Error: %s" % str(err))
            return False

    def insert_alert_evidence(self, identifier):
        """
        Insert given identifier into table
        :param identifier: alert_id + evidence_sha256 data to check duplicates
        :exception: when database connection error occurs
        :return Bool: status of insertion operation
        """
        try:
            alert_evidence = AlertEvidence(identifier=identifier)
            DatabaseConfig.session.add(alert_evidence)
            DatabaseConfig.session.commit()
            return True
        except Exception as err:
            self.log.error("Database Error: %s" % str(err))
            return False
