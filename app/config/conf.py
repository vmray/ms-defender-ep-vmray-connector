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
    SELECTED_DETECTION_SOURCES = [
        WINDOWS_DEFENDER_ATP,
        CUSTOMER_TI,
        WINDOWS_DEFENDER_AV,
    ]


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
    CLEAN = "clean"


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
        RESOURCE_APPLICATION_ID_URI = "https://api.securitycenter.microsoft.com"

        # URL to access Microsoft Defender for Endpoint API
        URL = "https://api.securitycenter.microsoft.com"

        # User-Agent value to use for Microsoft Defender for Endpoint API
        USER_AGENT = "MdePartner-VMRay-VMRayAnalyzer/4.4.1"

        # Azure BLOB details
        ACCOUNT_NAME = "<BLOB_ACCOUNT_NAME>"

        CONTAINER_NAME = "<BLOB_CONTAINER_NAME>"

        CONNECTION_STRING = "<CONNECTION_STRING>"

        SAS_TOKEN ="<BLOB_SAS_TOKEN>"


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

        # Max Retrying for get evidences  (seconds)
        MAX_GET_EVE_RETRY = 3

        # Retrying for get evidence after a delay (seconds)
        RETRY_GET_EVE_DELAY = 40

    # Machine action related configurations
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/machineaction
    class MACHINE_ACTION:
        # Specific machine action job timeout as seconds
        JOB_TIMEOUT = 180

        # Machine action timeout for machine itself
        MACHINE_TIMEOUT = 300

        # Sleep time for waiting the jobs as seconds
        SLEEP = 30

        # Retrying for live response after a delay (seconds)
        RETRY_LIVE_DELAY = 20

        # Max Retrying for live response
        MAX_LIVE_RETRY = 3


    # Indicator related configurations
    # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/ti-indicator
    class INDICATOR:
        # Enable or disable indicator submission
        ACTIVE = False

        # Action for indicators which created by connector
        ACTION = INDICATOR_ACTION.AUDIT

        # Title for indicators which created by connector
        TITLE = "Indicator based on VMRay Analyzer Report"

        # Description for indicators which created by connector
        DESCRIPTION = "Indicator based on VMRay Analyzer Report"

    class EDR_ENRICHMENT:
        # Enable or disable EDR related evidence enrichment with comments
        ACTIVE = True

        # Selected sections that will be added into comments
        SELECTED_SECTIONS = [
            ENRICHMENT_SECTION_TYPES.CLASSIFICATIONS,
            ENRICHMENT_SECTION_TYPES.THREAT_NAMES,
            ENRICHMENT_SECTION_TYPES.VTIS,
        ]

    class AV_ENRICHMENT:
        # Enable or disable AV related evidence enrichment with comments
        ACTIVE = False

        # Selected sections that will add into comments
        SELECTED_SECTIONS = [
            ENRICHMENT_SECTION_TYPES.CLASSIFICATIONS,
            ENRICHMENT_SECTION_TYPES.THREAT_NAMES,
            ENRICHMENT_SECTION_TYPES.VTIS,
        ]

    class INGESTION:
        # Enable or Disable ingestion from EDR module of MDE
        EDR_BASED_INGESTION = False

        # Enable or Disable ingestion from AV module of MDE
        AV_BASED_INGESTION = True

    # Alert polling time span as seconds
    TIME_SPAN = 10800

    # Library folder
    LIB_DIR = pathlib.Path("lib")

    # File name of the helper script that upload quarantined files to VMRay
    HELPER_SCRIPT_FILE_NAME = "SubmitEvidencesToVmray.ps1"

    # Helper script file path
    HELPER_SCRIPT_FILE_PATH = LIB_DIR / pathlib.Path(HELPER_SCRIPT_FILE_NAME)


# VMRay Configuration
class VMRayConfig:
    # VMRay API Key type setting
    API_KEY_TYPE = VMRAY_API_KEY_TYPE.REPORT

    # VMRay Report or Verdict API KEY
    API_KEY = (
        "<API_KEY>"
    )

    # VMRay REST API URL
    URL = "https://us.cloud.vmray.com"

    # User Agent string for VMRay Api requests
    CONNECTOR_NAME = "MicrosoftDefenderForEndpointConnector-1.0"

    # SSL Verification setting for self-signed certificates
    SSL_VERIFY = True

    # VMRay Submission Comment
    SUBMISSION_COMMENT = (
        "Sample from VMRay Analyzer - Microsoft Defender for Endpoint Connector"
    )

    # VMRay Submission Comment
    SUBMISSION_AV_TAGS = ["MicrosoftDefenferForEndpoint", "SubmittedFromEndpoint"]

    # VMRay submission tags (Can't contain space)
    SUBMISSION_TAGS = ["MicrosoftDefenferForEndpoint"]

    # VMRay analysis timeout value (seconds)
    ANALYSIS_TIMEOUT = 120

    # VMRay analysis job timeout for wait_submissions
    ANALYSIS_JOB_TIMEOUT = 300

    # VMRay retry submission delay (seconds)
    VMRAY_RETRY_DELAY = 20

    # VMRay max retry for submission
    VMRAY_MAX_RETRY = 3

    # Resubmission status for evidences which has been already analyzed by VMRay
    RESUBMIT = False

    # Selected verdicts to resubmit evidences
    RESUBMISSION_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS, VERDICT.CLEAN]


# General Configuration
class GeneralConfig:
    # Log directory
    LOG_DIR = pathlib.Path("log")

    # Log file path
    LOG_FILE_PATH = LOG_DIR / pathlib.Path("microsoft-defender-connector.log")

    # Log verbosity level
    LOG_LEVEL = log.INFO

    # Selected verdicts for processing
    SELECTED_VERDICTS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS, VERDICT.CLEAN]

    # Selected verdicts for indicators
    INDICATOR_VERDICTS = [VERDICT.SUSPICIOUS, VERDICT.MALICIOUS]

    # Time span between script iterations
    TIME_SPAN = 300

    # Runtime mode for script
    # If selected as CLI, script works only once, you need to create cron job for continuous processing
    # If selected as DOCKER, scripts works continuously with TIME_SPAN above
    RUNTIME_MODE = RUNTIME_MODE.CLI


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

    # Submission table name
    SUBMISSION_TABLE_NAME = "submissions"

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
