from app.config.conf import INDICATOR_ACTION

import base64


class LiveResponse:
    """
    LiveResponse class for storing live response job details
    """

    def __init__(self):
        self.index = 0
        self.has_error = False
        self.is_finished = False
        self.status = None
        self.id = None
        self.download_url = None
        self.timeout_counter = 0


class Evidence:
    """
    Evidence class for storing evidence related information
    """

    def __init__(self, sha256, sha1, file_name, file_path, alert_id, machine_id, detection_source, threat_name):
        self.sha256 = sha256
        self.sha1 = sha1
        self.file_name = file_name
        self.file_path = file_path
        self.absolute_path = self.file_path + "\\" + self.file_name
        self.alert_ids = {alert_id}
        self.machine_ids = {machine_id}
        self.detection_source = detection_source
        self.live_response = LiveResponse()
        self.comments = set()
        self.submissions = []
        self.need_to_submit = False
        self.threat_name = threat_name

    def set_comments(self, comments):
        for comment in comments:
            if "comment" in comment and comment["comment"] is not None:
                self.comments.add(base64.b64encode(comment["comment"].encode("utf-8")).decode("utf-8"))


class Machine:
    """
    Machine class for storing machine related information and evidences
    """

    def __init__(self, machine_id):
        self.id = machine_id
        self.edr_evidences = {}
        self.av_evidences = {}
        self.run_script_live_response_finished = False
        self.timeout_counter = 0

    def has_pending_edr_actions(self):
        """
        Check if the machine has pending live response jobs
        :return bool: status of pending live response jobs
        """
        for evidence in self.edr_evidences.values():
            # if there is evidence which is not finished and has no error, it must be pending
            # if there is at least one pending jobs, function returns True
            if not evidence.live_response.is_finished and not evidence.live_response.has_error:
                return True

        return False

    def get_successful_edr_evidences(self):
        return [evidence for evidence in self.edr_evidences.values() if evidence.live_response.download_url is not None]


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
