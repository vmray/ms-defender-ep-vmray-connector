from app.config.conf import INDICATOR_ACTION


class Machine:
    """
    Machine class for storing machine related information and evidences
    """

    def __init__(self, id):
        self.id = id
        self.evidences = []
        self.timeout_counter = 0

    def has_pending_actions(self):
        """
        Check if the machine has pending live response jobs
        :return bool: status of pending live response jobs
        """
        for evidence in self.evidences:
            # if there is evidence which is not finished and has no error, it must be pending
            # if there is at least one pending jobs, function returns True
            if not evidence.live_response.is_finished and not evidence.live_response.has_error:
                return True
        return False

    def get_successful_evidences(self):
        """
        Get evidence objects which successful live response jobs and download url
        :return list: list of evicence objects
        """
        return [evidence for evidence in self.evidences if evidence.download_url is not None]


class LiveResponse:
    """
    LiveResponse class for storing live response job details
    """

    def __init__(self):
        self.timeout_counter = 0
        self.has_error = False
        self.is_finished = False
        self.errors = None
        self.index = None
        self.status = None
        self.requested_at = None
        self.finished_at = None
        self.id = None

    def start(self, index, errors, status, requested_at, id):
        self.index = index
        self.errors = errors
        self.status = status
        self.requested_at = requested_at
        self.id = id
        self.timeout_counter = 0


class Evidence:
    """
    Evidence class for storing evidence related information and alerts/machines
    """

    def __init__(self, alert_id, severity, sha256, sha1, file_name, file_path, machine_id):
        self.alerts = {alert_id}
        self.severity = severity
        self.sha256 = sha256
        self.sha1 = sha1
        self.file_name = file_name
        self.file_path = file_path
        self.absolute_path = self.file_path + "\\" + self.file_name
        self.machines = {machine_id}
        self.download_url = None
        self.download_file_path = None
        self.already_processed = False
        self.vmray_sample = None
        self.live_response = LiveResponse()


class Indicator:
    """
    Indicator class for storing indicator related data
    """

    def __init__(self, type, value, action, application, title, description):
        self.type = type
        self.value = value
        self.action = action
        self.application = application
        self.title = title
        self.description = description
        self.generate_alert = False

        if action == INDICATOR_ACTION.AUDIT:
            self.generate_alert = True

    def serialize(self):
        """
        Serialize indicator object as dict
        Used for posting indicator objects with api request
        :return dict: serialized indicator data
        """
        return {
            "indicatorType": self.type,
            "indicatorValue": self.value,
            "action": self.action,
            "application": self.application,
            "title": self.title,
            "description": self.description,
            "generateAlert": self.generate_alert
        }
