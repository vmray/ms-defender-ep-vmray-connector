import sqlalchemy
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from app.config.conf import DatabaseConfig

Base = declarative_base()


class Evidence(Base):
    """
    Database ORM to store Evidence info for duplicate checking
    """

    __tablename__ = DatabaseConfig.TABLE_NAME
    id = Column(Integer, primary_key=True)
    machine_id = Column(String)
    alert_id = Column(String)
    evidence_sha256 = Column(String)


class Submission(Base):
    __tablename__ = DatabaseConfig.SUBMISSION_TABLE_NAME
    id = Column(Integer, primary_key=True)
    submission_id = Column(String)


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

    @staticmethod
    def check_submission_table_exists():
        """
        Check table exists with using DatabaseConfig
        :return: void
        """
        return sqlalchemy.inspect(DatabaseConfig.engine).has_table(DatabaseConfig.SUBMISSION_TABLE_NAME)

    def create_table(self):
        """
        Create table if not exists in the database
        :return: void
        """
        if not self.check_table_exists():
            Base.metadata.create_all(DatabaseConfig.engine)
            self.log.info("Creating %s table" % DatabaseConfig.TABLE_NAME)

        if not self.check_submission_table_exists():
            Base.metadata.create_all(DatabaseConfig.engine)
            self.log.info("Creating %s table" % DatabaseConfig.SUBMISSION_TABLE_NAME)

    def check_evidence_exists(self, machine_id, alert_id, evidence_sha256):
        """
        Check given identifier exists in the table
        :param machine_id: machine id for evidence
        :param alert_id: alert id for evidence
        :param evidence_sha256: sha256 of evidence
        :exception: when database connection error occurs
        :return Bool: existence status of identifier
        """
        try:
            evidence = DatabaseConfig.session.query(Evidence). \
                filter(Evidence.machine_id == machine_id). \
                filter(Evidence.alert_id == alert_id). \
                filter(Evidence.evidence_sha256 == evidence_sha256).first()
            return evidence
        except Exception as err:
            self.log.error("Database Error: %s" % str(err))
            return None

    def check_submission_exists(self, submission_id):
        try:
            submission = DatabaseConfig.session.query(Submission). \
                filter(Submission.submission_id == submission_id).first()
            return submission
        except Exception as err:
            self.log.error("Database Error: %s" % str(err))
            return None

    def insert_evidence(self, machine_id, alert_id, evidence_sha256):
        """
        Insert given identifier into table
        :param machine_id: machine id for evidence
        :param alert_id: alert id for evidence
        :param evidence_sha256: sha256 of evidence
        :exception: when database connection error occurs
        :return Bool: status of insertion operation
        """
        try:
            evidence = Evidence(machine_id=machine_id,
                                alert_id=alert_id,
                                evidence_sha256=evidence_sha256)
            DatabaseConfig.session.add(evidence)
            DatabaseConfig.session.commit()
            return True
        except Exception as err:
            self.log.error("Database Error: %s" % str(err))
            return False

    def insert_submission(self, submission_id):
        try:
            submission = Submission(submission_id=submission_id)
            DatabaseConfig.session.add(submission)
            DatabaseConfig.session.commit()
            return True
        except Exception as err:
            self.log.error("Database Error: %s" % str(err))
            return False
