import pathlib
import logging as log


# Runtime mode of connector
class RUNTIME_MODE:
    DOCKER = "DOCKER"
    CLI = "CLI"


# Microsoft Defender for Endpoint Evidence Entity Types
# Entity type can be Process, File, User, but we need only file
# Class can be extended for future use
class EVIDENCE_ENTITY_TYPE:
    FILE = "File"
    ALL = [FILE]


# Microsoft Defender for Endpoint Alert Detection Sources
# Detection type can be WindowsDefenderAtp, CustomerTI or WindowsDefenderAv
# Class can be extended for future detection types
class ALERT_DETECTION_SOURCE:
    WINDOWS_DEFENDER_ATP = "WindowsDefenderAtp"
    CUSTOMER_TI = "CustomerTI"
    WINDOWS_DEFENDER_AV = "WindowsDefenderAv"
    SELECTED_DETECTION_SOURCES = [WINDOWS_DEFENDER_ATP, CUSTOMER_TI, WINDOWS_DEFENDER_AV]


# Microsoft Defender for Endpoint Alert Severities
# Alert severities used for filtering alerts
# You can change ALL array or define new array with necessary changes
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/alerts
class ALERT_SEVERITY:
    UNSPECIFIED = "UnSpecified"
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    ALL = [UNSPECIFIED, INFORMATIONAL, LOW, MEDIUM, HIGH]


# Microsoft Defender for Endpoint Alert Statuses
# Alert statuses used for filtering alerts
# You can change ALL array or define new array with necessary changes
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/alerts
class ALERT_STATUS:
    UNKNOWN = "Unknown"
    NEW = "New"
    IN_PROGRESS = "InProgress"
    RESOLVED = "Resolved"
    ALL = [UNKNOWN, NEW, IN_PROGRESS, RESOLVED]


# Microsoft Defender for Endpoint Machine Action Statuses
# Machine action statuses used for checking current state or result of the machine action
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/machineaction
class MACHINE_ACTION_STATUS:
    PENDING = "Pending"
    IN_PROGRESS = "InProgress"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    TIMEOUT = "TimeOut"
    CANCELLED = "Cancelled"
    AVAILABLE = [SUCCEEDED, FAILED, TIMEOUT, CANCELLED]
    NOT_AVAILABLE = [PENDING, IN_PROGRESS]
    FAIL = [CANCELLED, TIMEOUT, FAILED]


# Microsoft Defender for Endpoint machine isolation types
# Isolation types used to define type of automated isolation triggered by connector
# Full: Full isolation
# Selective: Restrict only limited set of applications from accessing the network
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine
class ISOLATION_TYPE:
    FULL = "Full"
    SELECTIVE = "Selective"


# Microsoft Defender for Endpoint anti virus scan types
# Anti virus scan types used to define type of automated anti virus scan triggered by connector
# Quick: Perform quick scan on the device
# Full: Perform full scan on the device
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-av-scan
class ANTI_VIRUS_SCAN_TYPE:
    FULL = "Full"
    QUICK = "Quick"


# Microsoft Defender for Endpoint indicator actions
# Indicator actions used to define default action for auto created indicators by connector
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/ti-indicator
class INDICATOR_ACTION:
    ALLOWED = "Allowed"
    AUDIT = "Audit"
    BLOCK = "Block"
    BLOCK_AND_REMEDIATE = "BlockAndRemediate"
    WARN = "Warn"


# Microsoft Defender for Endpoint Enrichment Comment Section Types
class ENRICHMENT_SECTION_TYPES:
    CLASSIFICATIONS = "classifications"
    THREAT_NAMES = "threat_names"
    VTIS = "vtis"


# VMRay API Key types enum
class VMRAY_API_KEY_TYPE:
    REPORT = 0
    VERDICT = 1


# VMRay verdicts enum
class VERDICT:
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# VMRay job status
class JOB_STATUS:
    QUEUED = "queued"
    INWORK = "inwork"


# Microsoft Defender for Endpoint Configuration
class MicrosoftDefenderConfig:
    # API related configurations
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world
    class API:
        # Azure Active Directory Tenant Id
        # Used for programmatic API access through registered app
        TENANT_ID = "<TENANT_ID>"

        # Application ID which created to use this connector
        # Used for programmatic API access through registered app
        APPLICATION_ID = "<APPLICATION_ID>"

        # Application Secret ID which created to use this connector
        # Used for programmatic API access through registered app
        APPLICATION_SECRET_ID = "<APPLICATION_SECRET_ID>"

        # Application Secret which created to use this connector
        # Used for programmatic API access through registered app
        APPLICATION_SECRET = "<APPLICATION_SECRET>"

        # Application Name which created to use this connector
        # Used to define application name for submitted indicators
        APPLICATION_NAME = "VmrayDefenderFoEndpointConnectorApp"

        # Authentication Url to authenticate Azure Active Directory
        AUTH_URL = "https://login.microsoftonline.com/%s/oauth2/token" % TENANT_ID

        # Resource Application ID Uri to authenticate Azure Active Directory with created app
        RESOURCE_APPLICATION_ID_URI = 'https://api.securitycenter.microsoft.com'

        # URL to access Microsoft Defender for Endpoint API
        URL = "https://api.securitycenter.microsoft.com"

        # User-Agent value to use for Microsoft Defender for Endpoint API
        USER_AGENT = "MdePartner-VMRay-VMRayAnalyzer/4.4.1"

    # Download related configurations
    class DOWNLOAD:
        # Download directory name
        DIR = pathlib.Path("downloads")

        # Download directory path
        ABSOLUTE_PATH = pathlib.Path(__file__).parent.parent.resolve() / DIR

    # Alert related configurations
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/alerts
    class ALERT:
        # Selected Alert severities for filtering
        SEVERITIES = ALERT_SEVERITY.ALL

        # Selected Alert statuses for filtering
        STATUSES = ALERT_STATUS.ALL

        # Selected Evidence entity types for filtering
        EVIDENCE_ENTITY_TYPES = EVIDENCE_ENTITY_TYPE.ALL

        # Max alert count per request
        MAX_ALERT_COUNT = 10000

    # Machine action related configurations
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/machineaction
    class MACHINE_ACTION:
        # Specific machine action job timeout as seconds
        JOB_TIMEOUT = 180

        # Machine action timeout for machine itself
        MACHINE_TIMEOUT = 300

        # Sleep time for waiting the jobs as seconds
        SLEEP = 30

        # Isolation related configurations
        # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine
        class ISOLATION:
            # Automated isolation status
            ACTIVE = False

            # Selected VMRay Analyzer verdicts to isolate machine
            VERDICTS = [VERDICT.MALICIOUS]

            # Type of isolation
            TYPE = ISOLATION_TYPE.FULL

            # Comment for isolation job
            COMMENT = "Isolate machine based on VMRay Analyzer Report"

        # Anti virus scan related configurations
        # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-av-scan
        class ANTI_VIRUS_SCAN:
            # Automated anti virus scan status
            ACTIVE = False

            # Selected VMRay Analyzer verdicts to run antivirus scan
            VERDICTS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]

            # Type of anti virus scan job
            TYPE = ANTI_VIRUS_SCAN_TYPE.FULL

            # Comment for anti virus scan job
            COMMENT = "Run anti virus scan based on VMRay Analyzer Report"

        # Stop and Quarantine File action related configurations
        # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/stop-and-quarantine-file
        class STOP_AND_QUARANTINE_FILE:
            # Automated jobs status
            ACTIVE = False

            # Selected VMRay Analyzer verdicts to stop and quarantine file
            VERDICTS = [VERDICT.MALICIOUS]

            # Comment for stop and quarantine file job
            COMMENT = "Stop and quarantine files based on VMRay Analyzer Report"

        # Collect Investigation Package action related configurations
        class COLLECT_INVESTIGATION_PACKAGE:
            # Automated jobs status
            ACTIVE = False

            # Selected VMRay Analyzer verdicts to collect investigation package
            VERDICTS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]

            # Comment for collect investigation package job
            COMMENT = "Collect forensic investigation package based on VMRay Analyzer Report"

    # Indicator related configurations
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/ti-indicator
    class INDICATOR:
        # Enable or disable indicator submission
        ACTIVE = True

        # Action for indicators which created by connector
        ACTION = INDICATOR_ACTION.AUDIT

        # Title for indicators which created by connector
        TITLE = "Indicator based on VMRay Analyzer Report"

        # Description for indicators which created by connector
        DESCRIPTION = "Indicator based on VMRay Analyzer Report"

    class ENRICHMENT:
        # Enable or disable enrichment with comments
        ACTIVE = True

        # Selected sections that will add into comments
        SELECTED_SECTIONS = [ENRICHMENT_SECTION_TYPES.CLASSIFICATIONS,
                             ENRICHMENT_SECTION_TYPES.THREAT_NAMES,
                             ENRICHMENT_SECTION_TYPES.VTIS]

    # Alert polling time span as seconds
    TIME_SPAN = 3600


# VMRay Configuration
class VMRayConfig:
    # VMRay API Key type setting
    API_KEY_TYPE = VMRAY_API_KEY_TYPE.REPORT

    # VMRay Report or Verdict API KEY
    API_KEY = "<API_KEY>"

    # VMRay REST API URL
    URL = "https://eu.cloud.vmray.com"

    # User Agent string for VMRay Api requests
    CONNECTOR_NAME = "MicrosoftDefenderForEndpointConnector-1.0"

    # SSL Verification setting for self-signed certificates
    SSL_VERIFY = True

    # VMRay Submission Comment
    SUBMISSION_COMMENT = "Sample from VMRay Analyzer - Microsoft Defender for Endpoint Connector"

    # VMRay submission tags (Can't contain space)
    SUBMISSION_TAGS = ["MicrosoftDefenferForEndpoint"]

    # VMRay analysis timeout value (seconds)
    ANALYSIS_TIMEOUT = 120

    # VMRay analysis job timeout for wait_submissions
    ANALYSIS_JOB_TIMEOUT = 300

    # Resubmission status for evidences which has been already analyzed by VMRay
    RESUBMIT = False

    # Selected verdicts to resubmit evidences
    RESUBMISSION_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]


# General Configuration
class GeneralConfig:
    # Log directory
    LOG_DIR = pathlib.Path("log")

    # Log file path
    LOG_FILE_PATH = LOG_DIR / pathlib.Path("microsoft-defender-connector.log")

    # Log verbosity level
    LOG_LEVEL = log.INFO

    # Selected verdicts for processing
    SELECTED_VERDICTS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]

    # Time span between script iterations
    TIME_SPAN = 300

    # Runtime mode for script
    # If selected as CLI, script works only once, you need to create cron job for continuous processing
    # If selected as DOCKER, scripts works continuously with TIME_SPAN above
    RUNTIME_MODE = RUNTIME_MODE.DOCKER


# Database Configuration
# SQLite db using for eliminating duplicates
class DatabaseConfig:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # Database directory
    DB_DIR = pathlib.Path("db")

    # Database file path
    DB_PATH = DB_DIR / pathlib.Path("db.sqlite3")

    # Table name
    TABLE_NAME = "evidences"

    # Database connection string
    DATABASE_URI = "sqlite:///%s" % DB_PATH

    # Initializing db connection
    try:
        engine = create_engine(DATABASE_URI)
        Session = sessionmaker(bind=engine)
        session = Session()
    except Exception as err:
        print("Database connection error: %s" % str(err))
        log.error("Database connection error" % str(err))
        raise


# VMRay Analyzer and Microsoft Defender for Endpoint Indicator field mappings
# You can enable or disable IOC values with comments
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/ti-indicator
IOC_FIELD_MAPPINGS = {
    "ipv4": ["IpAddress"],

    "sha256": ["FileSha256"],

    "domain": ["DomainName"],

    "sha1": ["FileSha1"],

    "md5": ["FileMd5"],
}
