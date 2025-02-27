import hashlib
import io

from app.config.conf import MicrosoftDefenderConfig, MACHINE_ACTION_STATUS, ALERT_DETECTION_SOURCE, IOC_FIELD_MAPPINGS, ENRICHMENT_SECTION_TYPES
from app.lib.Models import Evidence, Indicator

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import json
import datetime
import base64
import gzip
import os
import pathlib
import shutil
import time
from datetime import datetime, timedelta
from azure.storage.blob import BlobServiceClient

class MicrosoftDefender:
    """
    Wrapper class for Microsoft Defender for Endpoint API calls
    Import this class to retrieve alerts, evidences and start live response jobs
    """

    def __init__(self, log, db):
        """
        Initialize and authenticate the MicrosoftDefender instance, use MicrosoftDefenderConfig as configuration
        :param log: logger instance
        :return: void
        """
        self.access_token = None
        self.headers = None
        self.config = MicrosoftDefenderConfig
        self.log = log
        self.db = db

        self.authenticate()

    def authenticate(self):
        """
        Authenticate using Azure Active Directory application properties, and retrieves the access token
        :raise: Exception when credentials/application properties are not properly configured
        :return: void
        """

        # defining request body with application properties and secret
        body = {
            "resource": self.config.API.RESOURCE_APPLICATION_ID_URI,
            "client_id": self.config.API.APPLICATION_ID,
            "client_secret": self.config.API.APPLICATION_SECRET,
            "grant_type": "client_credentials"
        }

        # posting defined request data to retrieve access token
        try:
            response = requests.post(url=self.config.API.AUTH_URL, data=body)
            data = json.loads(response.content)
            self.access_token = data["access_token"]
            self.headers = {"Authorization": "Bearer %s" % self.access_token, "User-Agent": self.config.API.USER_AGENT,
                            "Content-Type": "application/json"}
            self.log.debug("Successfully authenticated the Microsoft Defender for Endpoint API")
        except Exception as err:
            self.log.error(err)
            raise

    def upload_ps_script_to_library(self):
        # building request url
        request_url = self.config.API.URL + "/api/libraryfiles"

        mp_encoder = MultipartEncoder(
            fields={
                'HasParameters': 'false',
                'OverrideIfExists': 'true',
                'Description': 'description',
                'file': (self.config.HELPER_SCRIPT_FILE_NAME,
                         open(self.config.HELPER_SCRIPT_FILE_PATH, 'rb'),
                         'text/plain')
            }
        )

        # try-except block for handling api request exceptions

        try:
            # making api call with odata query and loading response as json
            response = requests.post(url=request_url,
                                     headers={**self.headers, **{'Content-Type': mp_encoder.content_type}},
                                     data=mp_encoder)
            json_response = json.loads(response.content)

            if response.status_code == 200:
                self.log.info("The helper script was successfully uploaded")
                return True
            else:
                # if api response contains the "error" key, should be an error about request
                if "error" in json_response:
                    self.log.error("Failed to upload the helper script - Error: %s" % (json_response["error"]["message"]))
        except Exception as err:
            self.log.error("Failed to upload helper script - Error: %s" % err)
        return False

    def get_evidences(self):
        """
        Retrieve alerts and related evidence information with error handling and retry logic.
        :exception: Handles cases when alerts and evidences cannot be retrieved properly.
        :return evidences: dict of evidence objects
        """

        # defining start_time for alerts with using configured TIME_SPAN
        # we need to use UTC because Microsoft Defender for Endpoint stores timestamps as UTC
        start_time = (datetime.utcnow() - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')

        # defining ODATA Query string for filtering alerts based on start_time, status and severity
        odata_query = "$filter=lastEventTime+ge+%s" % start_time
        odata_query += " and status in ('%s')" % "','".join(self.config.ALERT.STATUSES)
        odata_query += " and severity in ('%s')" % "','".join(self.config.ALERT.SEVERITIES)

        # adding necessary filter to retrieve evidences with alerts
        odata_query += "&$expand=evidence&"

        # adding necessary filter to define max alert count per request
        odata_query += "$top=%d" % self.config.ALERT.MAX_ALERT_COUNT

        # building final request url with odata query above
        request_url = self.config.API.URL + "/api/alerts?" + odata_query

        evidences = {}
        retries = 0

        while retries < self.config.ALERT.MAX_GET_EVE_RETRY:
            try:
                response = requests.get(url=request_url, headers=self.headers)

                # Handle HTTP errors
                if response.status_code == 429:  # Too many requests
                    self.log.warning(f"Rate limit exceeded. Retrying after {self.config.ALERT.RETRY_GET_EVE_DELAY}  sec delay...attempt : {retries+1}")
                    time.sleep(self.config.ALERT.RETRY_GET_EVE_DELAY)
                    retries += 1
                    continue
                elif response.status_code >= 500:  # Server errors
                    self.log.warning(f"Server error ({response.status_code}). Retrying after {self.config.ALERT.RETRY_GET_EVE_DELAY}  sec delay...attempt : {retries+1}")
                    time.sleep(self.config.ALERT.RETRY_GET_EVE_DELAY)
                    retries += 1
                    continue
                elif response.status_code not in [200, 201]:  # Other client errors
                    self.log.error(f"Failed to retrieve alerts. HTTP {response.status_code}: {response.text} Retrying after {self.config.ALERT.RETRY_GET_EVE_DELAY}  sec delay...attempt : {retries+1}")
                    time.sleep(self.config.ALERT.RETRY_GET_EVE_DELAY)
                    retries += 1
                    continue

                # Parse JSON response
                json_response = response.json()
                if "error" in json_response:
                    self.log.error(f"Failed to retrieve alerts - Error: {json_response['error']['message']}")
                    break

                if "value" in json_response:
                    raw_alerts = json_response["value"]
                    self.log.info(f"Successfully retrieved {len(raw_alerts)} alerts.")

                    # Process alerts and related evidence
                    for raw_alert in raw_alerts:
                        try:
                            if raw_alert["detectionSource"] in ALERT_DETECTION_SOURCE.SELECTED_DETECTION_SOURCES:
                                for evidence in raw_alert.get("evidence", []):
                                    evidence_sha256 = evidence.get("sha256")

                                    if (
                                            evidence["entityType"] in self.config.ALERT.EVIDENCE_ENTITY_TYPES
                                            and evidence_sha256
                                            and evidence_sha256.lower() != "none"
                                    ):
                                        if evidence_sha256 in evidences:
                                            evidences[evidence_sha256].alert_ids.add(raw_alert["id"])
                                            evidences[evidence_sha256].machine_ids.add(raw_alert["machineId"])
                                        else:
                                            evidence_entry = self.db.check_evidence_exists(
                                                machine_id=raw_alert["machineId"],
                                                alert_id=raw_alert["id"],
                                                evidence_sha256=evidence_sha256,
                                            )
                                            if evidence_entry is None:
                                                evidences[evidence_sha256] = Evidence(
                                                    sha256=evidence_sha256,
                                                    sha1=evidence.get("sha1"),
                                                    file_name=evidence.get("fileName"),
                                                    file_path=evidence.get("filePath"),
                                                    alert_id=raw_alert["id"],
                                                    machine_id=raw_alert["machineId"],
                                                    detection_source=raw_alert["detectionSource"],
                                                    threat_name=raw_alert["threatName"]
                                                )
                                                evidences[evidence_sha256].set_comments(raw_alert.get("comments", []))
                                            else:
                                                self.log.debug(
                                                    f"Evidence {evidence_sha256} already processed by connector.")
                        except Exception as err:
                            self.log.warning(f"Failed to parse alert object - Error: {err}")
                    self.log.info(f"Successfully processed {len(raw_alerts)} alerts and {len(evidences)} evidences.")
                else:
                    self.log.error("Failed to parse API response - 'value' key not found.")
                break

            except requests.ConnectionError:
                self.log.error("Failed to connect to the server. Retrying...")
            except requests.Timeout:
                self.log.error("Request timed out. Retrying...")
            except Exception as err:
                self.log.error(f"Unexpected error occurred: {err}")

            retries += 1
            if retries < self.config.ALERT.MAX_GET_EVE_RETRY:
                time.sleep(self.config.ALERT.RETRY_GET_EVE_DELAY)
            else:
                self.log.error("Max retries reached. Unable to retrieve evidences.")

        return evidences

    def get_machine_actions(self, machine_id):
        """
        Retrieve machine actions for given machine_id
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machineactions-collection
        :param machine_id: Microsoft Defender for Endpoint ID for the machine
        :exception: when machine actions are not properly retrieved
        :return list or None: list of machine actions or None if there is an error
        """

        # defining ODATA Query string for filtering machine actions based on machine_id
        odata_query = "$filter=machineId+eq+'%s'" % machine_id

        # building request url with odata query
        request_url = self.config.API.URL + "/api/machineactions?" + odata_query

        # try-except block for handling api request and parsing exceptions
        try:
            # making api call with odata query and loading response as json
            response = requests.get(url=request_url, headers=self.headers)
            json_response = json.loads(response.content)

            # if api response contains the "error" key, should be an error about request
            if "error" in json_response:
                self.log.error("Failed to retrieve actions for machine %s - Error: %s" % (
                    machine_id, json_response["error"]["message"]))
                return None
            else:
                # value key in json response contains machine actions
                # checking the "value" key as a second error control
                if "value" in json_response:
                    return json_response["value"]
                else:
                    self.log.error(
                        "Failed to parse api response for machine %s - Error: value key not found in dict" % (
                            machine_id))
                    return None
        except Exception as err:
            self.log.error("Failed to retrieve machine actions for machine %s - Error: %s" % (machine_id, err))
            return None

    def get_machine_action(self, live_response_id):
        """
        Retrieve machine action detail with given live_response_id string
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machineaction-object
        :param live_response_id: live response id
        :exception: when machine action is not properly retrieved
        :return dict or None: dict of machine action data or None if there is an error
        """

        # building request url with necessary endpoint and live response machine action id
        request_url = self.config.API.URL + "/api/machineactions/%s" % live_response_id

        # try-except block for handling api request exceptions
        try:
            # making api call and loading response as json
            response = requests.get(url=request_url, headers=self.headers)
            json_response = json.loads(response.content)

            # if api response contains the "error" key, should be an error about request
            if "error" in json_response:
                self.log.error("Failed to retrieve machine action detail for %s - Error: %s" % (
                    live_response_id, json_response["error"]["message"]))
                return None
            else:
                return json_response
        except Exception as err:
            self.log.error("Failed to retrieve machine action for %s - Error: %s" % (live_response_id, err))
            return None

    def is_machine_available(self, machine_id):
        """
        Check if the machine has no pending or processing machine action
        Because we can't make another machine action request when one of them pending
        :param machine_id: Microsoft Defender for Endpoint ID for the machine
        :return bool: machine availability status
        """

        # retrieving past machine action for machine
        machine_actions = self.get_machine_actions(machine_id)

        # if machine action is None, should be an error
        if machine_actions is not None:

            for action in machine_actions:

                # checking machine action status with configured values
                # if there is at least one pending or in_progress live response jobs, return False
                if action["status"] in MACHINE_ACTION_STATUS.NOT_AVAILABLE:
                    self.log.warning("Machine %s is busy. Current action type is %s and status is %s" % (
                        machine_id, action["type"], action["status"]))
                    return False

            # if there is no pending jobs, return True
            self.log.info("Machine %s is available" % machine_id)
            return True
        else:
            return False

    def cancel_machine_action(self, live_response_id):
        """
        Cancel the machine action with given live_response object
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/cancel-machine-action
        :param live_response: live response instance
        :exception: when machine action is not properly cancelled
        :return bool: status of cancellation request
        """

        is_action_cancelled = False

        while not is_action_cancelled:

            # building request url with necessary endpoint and live response machine action id
            request_url = self.config.API.URL + "/api/machineactions/%s/cancel" % live_response_id

            # try-except block for handling api request exceptions
            try:
                # json request body for cancellation request
                request_data = {"Comment": "Machine action was cancelled by VMRay Connector due to timeout"}

                # making api call with request body and loading response as json
                response = requests.post(url=request_url, data=json.dumps(request_data), headers=self.headers)
                json_response = json.loads(response.content)

                # if api response contains the "error" key, should be an error about request
                # if there is an error, return False
                if "error" in json_response:
                    self.log.error("Failed to cancel machine action for %s - Error: %s" % (
                        live_response_id, json_response["error"]))
                else:
                    if json_response["status"] == "Cancelled" or json_response["status"] == "Failed":
                        self.log.info("Cancelled live response action %s" % live_response_id)
                        is_action_cancelled = True
            except Exception as err:
                self.log.error("Failed to cancel machine action for %s - Error: %s" % (live_response_id, err))

    def wait_run_script_live_response(self, live_response_id):
        timeout_counter = 0
        has_error = False
        is_finished = False

        self.log.info("Waiting live response job %s to finish" % live_response_id)

        # loop until the live response job timeout is exceeded or live response job failed/finished
        # we use JOB_TIMEOUT / SLEEP to check job status multiple in timeout duration
        while self.config.MACHINE_ACTION.JOB_TIMEOUT / self.config.MACHINE_ACTION.SLEEP > timeout_counter \
                and not has_error \
                and not is_finished:

            # initial sleep for newly created live response job
            time.sleep(self.config.MACHINE_ACTION.SLEEP)

            # retrieve live response job detail and status
            machine_action = self.get_machine_action(live_response_id)

            # if there is an error with machine action, set live response status failed
            # else process the machine_action details
            if machine_action is not None:

                # if machine action status is SUCCEEDED, set live response status finished
                if machine_action["status"] == MACHINE_ACTION_STATUS.SUCCEEDED:
                    self.log.info("Live response job %s finished" % live_response_id)
                    is_finished = True

                # if machine action status is FAIL, set live response status failed
                elif machine_action["status"] in MACHINE_ACTION_STATUS.FAIL:
                    self.log.error("Live response job %s failed with error" % live_response_id)
                    has_error = True

                # else increment the live response timeout counter to check timeout in While loop
                else:
                    timeout_counter += 1
            else:
                has_error = True

        # if job timeout limit is exceeded, set live response status failed
        if self.config.MACHINE_ACTION.JOB_TIMEOUT / self.config.MACHINE_ACTION.SLEEP <= timeout_counter:
            error_message = "Live response job timeout was hit (%s seconds)" % self.config.MACHINE_ACTION.JOB_TIMEOUT
            self.log.error("Live response job %s failed with error - Error: %s" % (
                live_response_id, error_message))
            has_error = True

            # cancel machine action to proceed other evidences in machines
            self.cancel_machine_action(live_response_id)
            # waiting cancelled machine action to stop
            time.sleep(self.config.MACHINE_ACTION.SLEEP)

        if has_error:
            return False

        return True


    def wait_live_response(self, live_response):
        """
        Waits for the live response machine action job to finish with retry logic and improved error handling.

        :param live_response: live_response object
        :param self.config.MACHINE_ACTION.MAX_LIVE_RETRY: Maximum number of retries for fetching machine action
        :param self.config.MACHINE_ACTION.RETRY_LIVE_DELAY: Delay (in seconds) between retries
        :return live_response: Modified live_response object with status
        """
        self.log.info("Waiting for live response job %s to finish" % live_response.id)

        while (
                live_response.timeout_counter < (
                self.config.MACHINE_ACTION.JOB_TIMEOUT / self.config.MACHINE_ACTION.SLEEP)
                and not live_response.has_error
                and not live_response.is_finished
        ):
            time.sleep(self.config.MACHINE_ACTION.SLEEP)

            retries = 0
            machine_action = None

            while retries < self.config.MACHINE_ACTION.MAX_LIVE_RETRY:
                try:
                    machine_action = self.get_machine_action(live_response.id)
                    if machine_action:
                        break
                except Exception as e:
                    self.log.warning("Attempt %d: Failed to fetch machine action for job %s - %s" % (
                    retries + 1, live_response.id, str(e)))
                    time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                    retries += 1

            if machine_action is None:
                self.log.error("Unable to retrieve machine action after %d attempts" % self.config.MACHINE_ACTION.MAX_LIVE_RETRY)
                live_response.has_error = True
                break

            if machine_action["status"] == MACHINE_ACTION_STATUS.SUCCEEDED:
                self.log.info("Live response job %s finished successfully" % live_response.id)
                live_response.status = machine_action["status"]
                live_response.is_finished = True
            elif machine_action["status"] in MACHINE_ACTION_STATUS.FAIL:
                self.log.error("Live response job %s failed with error" % live_response.id)

                retry_count = 0
                while retry_count < self.config.MACHINE_ACTION.MAX_LIVE_RETRY:
                    self.log.info(
                        "Retrying live response job %s (%d/%d)" % (live_response.id, retry_count + 1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY))
                    time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                    retry_count += 1
                    machine_action = self.get_machine_action(live_response.id)
                    if machine_action and machine_action["status"] == MACHINE_ACTION_STATUS.SUCCEEDED:
                        # self.log.info(f"Live response job %s recovered and finished successfully" % live_response.id)
                        self.log.info(f"Live response job {live_response.id} recovered and finished successfully")
                        live_response.status = machine_action["status"]
                        live_response.is_finished = True
                        break
                else:
                    self.log.error(f"Live response job {live_response.id} permanently failed after {self.config.MACHINE_ACTION.MAX_LIVE_RETRY} retries")

                    live_response.status = machine_action["status"]
                    live_response.has_error = True
            else:
                live_response.timeout_counter += 1

        if live_response.timeout_counter >= (self.config.MACHINE_ACTION.JOB_TIMEOUT / self.config.MACHINE_ACTION.SLEEP):
            error_message = "Live response job timeout was hit (%s seconds)" % self.config.MACHINE_ACTION.JOB_TIMEOUT
            self.log.error("Live response job %s failed with timeout error - %s" % (live_response.id, error_message))
            live_response.has_error = True
            live_response.status = MACHINE_ACTION_STATUS.TIMEOUT

            self.cancel_machine_action(live_response.id)
            time.sleep(self.config.MACHINE_ACTION.SLEEP)

        return live_response


    def get_live_response_result(self, live_response):
        """
        Retrieve live response result and download URL with improved stability and retry logic.

        :param live_response: live_response object instance
        :param self.config.MACHINE_ACTION.MAX_LIVE_RETRY: Maximum number of retries in case of failure
        :param self.config.MACHINE_ACTION.RETRY_LIVE_DELAY: Delay (in seconds) between retries
        :return: live_response object with updated download URL or error flag
        """

        request_url = self.config.API.URL + "/api/machineactions/%s/GetLiveResponseResultDownloadLink(index=%s)" % (
                     live_response.id, live_response.index)

        for attempt in range(1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY + 1):
            try:
                response = requests.get(url=request_url, headers=self.headers, timeout=10)

                # Handle HTTP errors
                if response.status_code >= 500:
                    self.log.warning(f"Server error ({response.status_code}) on attempt {attempt}. Retrying...")
                elif response.status_code == 429:
                    self.log.warning(f"Rate limit hit. Waiting {self.config.MACHINE_ACTION.RETRY_LIVE_DELAY} seconds before retrying...")
                elif response.status_code != 200:
                    self.log.error(
                        f"Failed to retrieve live response results ({response.status_code}): {response.text}")
                    break  # Non-retryable error
                else:
                    json_response = response.json()

                    if "error" in json_response:
                        self.log.error(
                            f"Error retrieving live response results for {live_response.id}: {json_response['error']['message']}")
                        live_response.has_error = True
                    elif "value" in json_response:
                        live_response.download_url = json_response["value"]
                        return live_response  # Success, return early
                    else:
                        self.log.error(f"Invalid response format for {live_response.id}: Missing 'value' key")
                        live_response.has_error = True
                    break  # Stop retrying on valid response with error

            except (requests.RequestException, json.JSONDecodeError) as err:
                self.log.error(f"Request failed on attempt {attempt} for {live_response.id}: {err}")

            if attempt < self.config.MACHINE_ACTION.MAX_LIVE_RETRY:
                time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)  # Wait before retrying

        live_response.has_error = True
        return live_response

    def run_edr_live_response(self, machines):
        """
        Process machines to start and manage live response jobs for gathering files using EDR.
        """

        for machine in machines:
            if not machine.edr_evidences:
                continue

            self.log.info(
                "Starting live response jobs for machine %s with %d evidences"
                % (machine.id, len(machine.edr_evidences))
            )

            while (
                    machine.timeout_counter < self.config.MACHINE_ACTION.MACHINE_TIMEOUT // self.config.MACHINE_ACTION.SLEEP
                    and machine.has_pending_edr_actions()
            ):
                if not self.is_machine_available(machine.id):
                    time.sleep(self.config.MACHINE_ACTION.SLEEP)
                    machine.timeout_counter += 1
                    continue

                for evidence in machine.edr_evidences.values():
                    if not self.is_machine_available(machine.id):
                        time.sleep(self.config.MACHINE_ACTION.SLEEP)
                        continue

                    live_response_command = {
                        "Commands": [
                            {
                                "type": "GetFile",
                                "params": [
                                    {"key": "Path", "value": evidence.absolute_path}
                                ],
                            }
                        ],
                        "Comment": "File acquisition for %s" % evidence.sha256,
                    }


                    request_url = self.config.API.URL + "/api/machines/%s/runliveresponse" % machine.id

                    retries = 0
                    while retries < self.config.MACHINE_ACTION.MAX_LIVE_RETRY:
                        try:
                            self.log.info(
                                "Starting live response job for evidence %s on machine %s (Attempt %d/%d, Retry Delay: %ds)"
                                % (evidence.absolute_path, machine.id, retries + 1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY, self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                            )

                            response = requests.post(
                                request_url,
                                data=json.dumps(live_response_command),
                                headers=self.headers,
                            )

                            if response.status_code not in (200, 201):
                                self.log.error(
                                    "Failed to initiate live response for machine %s, evidence %s - HTTP %d (Attempt %d/%d, Retry Delay: %ds)"
                                    % (machine.id, evidence.sha256, response.status_code, retries + 1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY,
                                       self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                                )
                                retries += 1
                                time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                                continue

                            json_response = response.json()

                            if "error" in json_response:
                                self.log.error(
                                    "Live response error for machine %s, evidence %s - Error: %s (Attempt %d/%d, Retry Delay: %ds)"
                                    % (
                                        machine.id,
                                        evidence.sha256,
                                        json_response["error"].get("message", "Unknown error"),
                                        retries + 1,
                                        self.config.MACHINE_ACTION.MAX_LIVE_RETRY,
                                        self.config.MACHINE_ACTION.RETRY_LIVE_DELAY
                                    )
                                )
                                retries += 1
                                time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                                continue

                            time.sleep(5)
                            action_response = self.get_machine_action(json_response["id"])

                            if action_response:
                                for command in action_response.get("commands", []):
                                    if command["command"].get("type") == "GetFile":
                                        evidence.live_response.index = command["index"]
                                        evidence.live_response.id = action_response["id"]

                                self.log.info(
                                    "Live response job %s for evidence %s started successfully"
                                    % (evidence.live_response.id, evidence.sha256)
                                )

                                evidence.live_response = self.wait_live_response(evidence.live_response)

                                if evidence.live_response.is_finished:
                                    evidence.live_response = self.get_live_response_result(
                                        evidence.live_response
                                    )
                                break  # Break out of retry loop on success
                            else:
                                self.log.error(
                                    "Failed to retrieve live response details for machine %s (Attempt %d/%d, Retry Delay: %ds)"
                                    % (machine.id, retries + 1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY, self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                                )
                                retries += 1
                                time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)

                        except requests.exceptions.RequestException as req_err:
                            self.log.error(
                                "Request error during live response for machine %s - Error: %s (Attempt %d/%d, Retry Delay: %ds)"
                                % (machine.id, req_err, retries + 1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY, self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                            )
                            retries += 1
                            time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)

                        except Exception as err:
                            self.log.error(
                                "Unexpected error during live response for machine %s - Error: %s (Attempt %d/%d, Retry Delay: %ds)"
                                % (machine.id, err, retries + 1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY, self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                            )
                            retries += 1
                            time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)

                    if retries == self.config.MACHINE_ACTION.MAX_LIVE_RETRY:
                        evidence.live_response.has_error = True

            if machine.has_pending_edr_actions():
                self.log.error(
                    "Machine %s was not available within timeout (%s seconds)"
                    % (machine.id, self.config.MACHINE_ACTION.MACHINE_TIMEOUT)
                )

        return machines

    def run_av_submission_script(self, machines):
        # Iterating machines to start live response jobs
        for machine in machines:
            if len(machine.av_evidences) > 0:
                self.log.info("Waiting to start run script live response job for machine %s" % machine.id)
                file_names = []
                threat_name = set()
                for evidence in machine.av_evidences.values():
                    file_names.append(evidence.file_name)
                    threat_name.add(evidence.threat_name)
                while (
                        self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP > machine.timeout_counter
                        and not machine.run_script_live_response_finished
                ):
                    if self.is_machine_available(machine.id):
                        args_param = f"{'vmray'.join(list(threat_name))},{self.config.API.ACCOUNT_NAME},{self.config.API.CONTAINER_NAME},{'vmray'.join(file_names)}"
                        live_response_command = {
                            "Commands": [
                                {
                                    "type": "RunScript",
                                    "params": [
                                        {
                                            "key": "ScriptName",
                                            "value": self.config.HELPER_SCRIPT_FILE_NAME

                                        },
                                        {
                                            "key": "Args",
                                            "value": args_param
                                        }
                                    ]
                                }
                            ],
                            "Comment": "Live response job to submit evidences to VMRay"
                        }

                        request_url = self.config.API.URL + "/api/machines/%s/runliveresponse" % machine.id

                        attempts = 0

                        while attempts < self.config.MACHINE_ACTION.MAX_LIVE_RETRY:
                            try:
                                response = requests.post(request_url, data=json.dumps(live_response_command),
                                                         headers=self.headers)
                                if response.status_code in (200, 201):
                                    json_response = response.json()
                                    if "error" in json_response:
                                        error_message = json_response["error"].get("message", "Unknown error")
                                        self.log.error("Run script live response error for machine %s - Error: %s" % (
                                        machine.id, error_message))

                                        if "device not connected" in error_message.lower():
                                            self.log.warning("Device %s is not connected. Skipping..." % machine.id)
                                            break
                                        elif "too many requests" in error_message.lower() or "temporary server error" in error_message.lower() or "active live response session" in error_message.lower():
                                            self.log.warning("Retryable error occurred. Retrying... (%d/%d)" % (
                                            attempts + 1, self.config.MACHINE_ACTION.MAX_LIVE_RETRY))
                                            time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                                            attempts += 1
                                            continue
                                        else:
                                            break
                                    else:
                                        self.log.info(
                                            "Run script live response job successfully created for machine %s" % machine.id)
                                        if "id" in json_response:
                                            live_response_id = json_response["id"]
                                            result = self.wait_run_script_live_response(live_response_id)

                                            if result:
                                                machine.run_script_live_response_finished = True
                                                self.log.info(
                                                    "Run script live response job successfully finished for machine %s" % machine.id)
                                            else:
                                                self.log.error(
                                                    "Live response job failed or timed out for machine %s" % machine.id)
                                        break
                                else:
                                    self.log.error("HTTP error %s while starting live response for machine retrying %s" % (
                                    response.status_code, machine.id))
                                    attempts += 1
                                    time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                            except requests.exceptions.RequestException as req_err:
                                self.log.error("Network error for machine %s - Error: %s" % (machine.id, req_err))
                                attempts += 1
                                time.sleep(self.config.MACHINE_ACTION.RETRY_LIVE_DELAY)
                            except ValueError as val_err:
                                self.log.error(
                                    "Failed to parse JSON response for machine %s - Error: %s" % (machine.id, val_err))
                                break
                            except Exception as err:
                                self.log.error("Unexpected error for machine %s - Error: %s" % (machine.id, err))
                                break
                    else:
                        time.sleep(self.config.MACHINE_ACTION.SLEEP)

                    machine.timeout_counter += 1

        return machines


    def download_evidences(self, evidences):
        """
        Download and extract evidence files
        :param evidences: list of evidence objects
        :exception: when evidence file is not properly downloaded or extracted
        :return evidences: list of evidence objects with downloaded file_path
        """

        # initial list to store successfully downloaded evidences
        downloaded_evidences = []
        self.log.info("Downloading %d evidences" % len(evidences))

        for evidence in evidences:
            if evidence.live_response.download_url is not None:
                self.log.info("Downloading evidence %s" % evidence.sha256)

                # try-except block for handling download request errors
                try:
                    # download file and store it in response object
                    response = requests.get(evidence.live_response.download_url, stream=True)

                    # initialize path variables for downloaded file
                    file_path = self.config.DOWNLOAD.ABSOLUTE_PATH / pathlib.Path(evidence.file_name + ".gz")
                    unzipped_file_path = self.config.DOWNLOAD.ABSOLUTE_PATH / pathlib.Path(evidence.file_name)
                    self.log.info("Evidence %s downloaded successfully. Response code: %d" % (
                        evidence.sha256, response.status_code))

                    # try-except block for handling file write errors
                    try:
                        # writing downloaded evidence file into disk as chunks
                        with open(file_path, "wb") as file:
                            for chunk in response.iter_content(1024):
                                if chunk:
                                    file.write(chunk)
                        self.log.info("Evidence %s saved successfully" % evidence.sha256)

                        # try-except block for handling gzip extraction errors
                        try:
                            # extracting gzip saved file
                            with gzip.open(file_path, "rb") as compressed:
                                with open(unzipped_file_path, "wb") as decompressed:
                                    shutil.copyfileobj(compressed, decompressed)

                            # if extracting successfull, delete gzip file
                            os.remove(file_path)
                            self.log.info("Evidence %s extracted successfully" % evidence.sha256)

                            # set evidence file path and append it to list
                            evidence.download_file_path = unzipped_file_path
                            downloaded_evidences.append(evidence)
                        except Exception as err:
                            self.log.error("Failed to extract evidence %s - Error: %s" % (evidence.sha256, err))
                    except Exception as err:
                        self.log.error(
                            "Failed to write evidence %s to %s - Error: %s" % (evidence.sha256, file_path, err))
                except Exception as err:
                    self.log.error("Failed to download evidence %s - Error: %s" % (evidence.sha256, err))
        return downloaded_evidences

    def get_indicators(self):
        """
        Retrieve unique indicators from Microsoft Defender for Endpoint
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-ti-indicators
        :exception: when indicators are not properly retrieved
        :return indicators: set of indicators
        """

        # building request url with url and necessary path
        request_url = self.config.API.URL + "/api/indicators"

        # defining initial set for storing indicator values
        indicators = set()

        # try-except block for handling api request and parsing exceptions
        try:
            # making api call and loading response as json
            response = requests.get(url=request_url, headers=self.headers)
            json_response = json.loads(response.content)

            # if api response contains the "error" key, should be an error about request
            if "error" in json_response:
                self.log.error("Failed to retrieve indicators - Error: %s" % json_response["error"]["message"])
                return indicators
            else:
                # value key in json response contains indicators
                # checking the "value" key as a second error control
                if "value" in json_response:
                    for indicator in json_response["value"]:
                        # adding only value to check duplicates easily
                        indicators.add(indicator["indicatorValue"])
                else:
                    self.log.error("Failed to retrieve indicators - Error: value key not found")
                    return indicators
        except Exception as err:
            self.log.error("Failed to retrieve indicators - Error %s" % err)
            return indicators

        self.log.info("%d unique indicator retrieved in total" % (len(indicators)))

        return indicators

    def create_indicator_objects(self, indicator_data, old_indicators):
        """
        Create indicators objects based on VMRay Analyzer indicator data and retrieved indicators from Microsoft Defender for Endpoint
        :param indicator_data: dict of indicators which retrieved from VMRay submission
        :param old_indicators: set of indicators which retrieved from Microsoft Defender for Endpoint
        :return indicator_objects: list of indicator objects
        """

        indicator_objects = []

        # iterate indicator types
        for key in indicator_data:

            # if configured IOC_FIELD_MAPPINGS dict has indicator type as key
            if key in IOC_FIELD_MAPPINGS.keys():

                # iterate IOC_FIELD_MAPPINGS values to map VMRay indicator types to Microsoft Defender for Endpoint
                for indicator_field in IOC_FIELD_MAPPINGS[key]:
                    indicator_value = indicator_data[key]

                    for indicator in indicator_value:

                        # duplicate check with old indicators
                        if indicator not in old_indicators:
                            indicator_objects.append(Indicator(type=indicator_field,
                                                               value=indicator,
                                                               action=self.config.INDICATOR.ACTION,
                                                               application=self.config.API.APPLICATION_NAME,
                                                               title=self.config.INDICATOR.TITLE,
                                                               description=self.config.INDICATOR.DESCRIPTION))

        return indicator_objects

    def submit_indicators(self, indicators):
        """
        Submit indicators to Microsoft Defender for Endpoint
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/post-ti-indicator
        :param indicators: list of indicator objects
        :exception: when indicators are not submitted properly
        :return void:
        """
        self.log.info("%d indicators submitting to Microsoft Defender for Endpoint" % len(indicators))

        # building request url with necessary endpoint
        request_url = self.config.API.URL + "/api/indicators"

        for indicator in indicators:
            # try-except block for handling api request errors
            try:
                # send post request with indicator object as json body
                response = requests.post(url=request_url, data=json.dumps(indicator.serialize()), headers=self.headers)
                if response.status_code == 200:
                    self.log.debug("Indicator %s submitted successfully" % indicator.value)
                else:
                    self.log.error("Failed to submit indicator - Error: %s" % response.content)
            except Exception as err:
                self.log.error("Failed to submit indicator %s - Error: %s" % (indicator.value, err))

    def list_all_blob(self, machines):
        # List all file(blob) uploaded by powershell scripts during the AV alerts.
        # Return list of file object and delete the blob from container,
        file_objects = []
        try:
            for machine in machines:
                if machine.run_script_live_response_finished:
                    # Create BlobServiceClient using the connection string
                    blob_service_client = BlobServiceClient.from_connection_string(
                        self.config.API.CONNECTION_STRING)

                    # Get a client to interact with the container
                    container_client = blob_service_client.get_container_client(
                        self.config.API.CONTAINER_NAME)

                    # List all blobs in the container

                    blobs = container_client.list_blobs()
                    for blob in blobs:
                        # Download the blob's content
                        blob_client = container_client.get_blob_client(blob.name)
                        blob_data = blob_client.download_blob().readall()
                        sha256_hash = hashlib.sha256(blob_data).hexdigest()
                        file_obj = io.BytesIO(blob_data)
                        file_obj.name = blob.name
                        file_objects.append({sha256_hash: file_obj})
                        container_client.delete_blob(blob.name)
                    self.log.info(f"fetched {len(file_objects)} blobs")
            return file_objects

        except Exception as ex:
            self.log.info(
                f"error occured while getting blobs: {ex}; Possible reasons are missing Connection String or SAS token.")
            return file_objects

    def enrich_alerts(self, evidence, sample_data, sample_vtis, enrichment_sections):
        """
        Enrich alerts with VMRay Analyzer submission metadata
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/update-alert
        :param evidence: evidence object
        :param sample_data: dict object which contains summary data about the sample
        :param sample_vtis: dict object which contains parsed VTI data about the sample
        :exception: when alert is not updated properly
        :return void:
        """

        # building comment object as text

        # adding evidence sha256
        comment = "Evidence SHA256:\n"
        comment += sample_data["sample_sha256hash"] + "\n\n"

        # adding VMRay Analyzer Verdict
        comment += "VMRAY Analyzer Verdict: %s\n\n" % sample_data["sample_verdict"].upper()

        # adding VMRay Analyzer sample url
        comment += "Sample Url:\n"
        comment += sample_data["sample_webif_url"] + "\n\n"

        if ENRICHMENT_SECTION_TYPES.CLASSIFICATIONS in enrichment_sections:
            # adding VMRay Analyzer sample classifications
            comment += "Classifications:\n"
            comment += "\n".join(sample_data["sample_classifications"]) + "\n\n"

        if ENRICHMENT_SECTION_TYPES.THREAT_NAMES in enrichment_sections:
            # adding VMRay Analyzer threat names
            comment += "Threat Names:\n"
            comment += "\n".join(sample_data["sample_threat_names"]) + "\n\n"

        if ENRICHMENT_SECTION_TYPES.VTIS in enrichment_sections:
            # adding VMRay Analyzer VTI's
            comment += "VTI's:\n"
            comment += "\n".join(list(set([vti["operation"] for vti in sample_vtis]))) + "\n\n"

        if base64.b64encode(comment.encode("utf-8")).decode("utf-8") not in evidence.comments:
            # iterating alerts related with given evidences
            for alert_id in evidence.alert_ids:

                # try-except block for handling api request exceptions
                try:
                    # building request body as json
                    request_data = {"comment": comment}

                    # building request_url with necessary endpoint and given alert_id
                    request_url = self.config.API.URL + "/api/alerts/%s" % alert_id

                    # making api call
                    response = requests.patch(request_url, data=json.dumps(request_data), headers=self.headers)

                    if response.status_code != 200:
                        self.log.error("Failed to update alert %s - Error: %s" % (alert_id, response.content))

                except Exception as err:
                    self.log.error("Failed to update alert %s - Error: %s" % (alert_id, err))

    def collect_investigation_package(self, evidence):
        """
        Collect investigation package from machines for given evidence
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/collect-investigation-package
        :param evidence: evidence object
        :exception: when collection failed
        :return void:
        """
        self.log.info("Collecting investigation package on %d machines" % len(evidence.machine_ids))

        # iterating machines which contains given evidence
        for machine_id in evidence.machine_ids:

            self.log.info("Collecting investigation package on machine %s" % machine_id)

            # building request url with necessary endpoint and machine_id
            request_url = self.config.API.URL + "/api/machines/%s/collectInvestigationPackage" % machine_id

            # set timeout_count for machine availability checks
            timeout_count = 0

            # set jos status flag for while loop
            is_job_pending = True

            # loop until machine action timeout exceeded or job finished/failed
            while self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP > timeout_count and is_job_pending:

                # check if machine is available
                if self.is_machine_available(machine_id):

                    # try-except block for handling api request exceptions
                    try:

                        # building isolation request body as dict
                        request_data = {
                            "Comment": self.config.MACHINE_ACTION.COLLECT_INVESTIGATION_PACKAGE.COMMENT,
                        }

                        # making api call loading response as json
                        response = requests.post(request_url, data=json.dumps(request_data), headers=self.headers)
                        json_response = json.loads(response.content)

                        # if api response contains the "error" key, should be an error about request
                        if "error" in json_response:
                            self.log.error("Failed to collect investigation package on machine %s - Error: %s" % (
                                machine_id, json_response["error"]["message"]))
                            is_job_pending = False
                        else:
                            self.log.info("Machine %s investigation package collection job started" % machine_id)
                            is_job_pending = False

                    except Exception as err:
                        self.log.error(
                            "Failed to collect investigation package on machine %s - Error: %s" % (machine_id, err))
                        is_job_pending = False
                else:
                    # increment timeout counter for timeout check
                    timeout_count += 1

                    # sleep and wait pending machine actions to finish
                    time.sleep(self.config.MACHINE_ACTION.SLEEP)

            # if timeout exceeded, machine action job has failed
            if self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP <= timeout_count:
                error_message = "Machine was not available during the timeout (%s seconds)" % self.config.MACHINE_ACTION.MACHINE_TIMEOUT
                self.log.error(
                    "Failed to collect investigation package on machine %s - Error: %s" % (machine_id, error_message))
            # else wait successful machine action job to finish
            else:
                time.sleep(self.config.MACHINE_ACTION.SLEEP)

    def run_antivirus_scan(self, evidence):
        """
        Run antivirus scan on machines for given evidence
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-av-scan
        :param evidence: evidence object
        :exception: when isolation failed
        :return void:
        """
        self.log.info("Running antivirus scan on %d machines" % len(evidence.machine_ids))

        # iterating machines which contains given evidence
        for machine_id in evidence.machine_ids:

            self.log.info("Running antivirus scan on machine %s" % machine_id)

            # building request url with necessary endpoint and machine_id
            request_url = self.config.API.URL + "/api/machines/%s/runAntiVirusScan" % machine_id

            # set timeout_count for machine availability checks
            timeout_count = 0

            # set jos status flag for while loop
            is_job_pending = True

            # loop until machine action timeout exceeded or job finished/failed
            while self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP > timeout_count and is_job_pending:

                # check if machine is available
                if self.is_machine_available(machine_id):

                    # try-except block for handling api request exceptions
                    try:

                        # building isolation request body as dict
                        request_data = {
                            "Comment": self.config.MACHINE_ACTION.ANTI_VIRUS_SCAN.COMMENT,
                            "ScanType": self.config.MACHINE_ACTION.ANTI_VIRUS_SCAN.TYPE
                        }

                        # making api call loading response as json
                        response = requests.post(request_url, data=json.dumps(request_data), headers=self.headers)
                        json_response = json.loads(response.content)

                        # if api response contains the "error" key, should be an error about request
                        if "error" in json_response:
                            self.log.error("Failed to run anti virus scan on machine %s - Error: %s" % (
                                machine_id, json_response["error"]["message"]))
                            is_job_pending = False
                        else:
                            self.log.info("Machine %s anti virus scan job started" % machine_id)
                            is_job_pending = False

                    except Exception as err:
                        self.log.error("Failed to run anti virus scan on machine %s - Error: %s" % (machine_id, err))
                        is_job_pending = False
                else:
                    # increment timeout counter for timeout check
                    timeout_count += 1

                    # sleep and wait pending machine actions to finish
                    time.sleep(self.config.MACHINE_ACTION.SLEEP)

            # if timeout exceeded, machine action job has failed
            if self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP <= timeout_count:
                error_message = "Machine was not available during the timeout (%s seconds)" % self.config.MACHINE_ACTION.MACHINE_TIMEOUT
                self.log.error("Failed to run anti virus scan on machine %s - Error: %s" % (machine_id, error_message))
            # else wait successful machine action job to finish
            else:
                time.sleep(self.config.MACHINE_ACTION.SLEEP)

    def stop_and_quarantine_file(self, evidence):
        """
        Stop and quarantine evidence file for affected machines
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/stop-and-quarantine-file
        :param evidence: evidence object
        :exception: when isolation failed
        :return void:
        """
        self.log.info("Stop and Quarantine file job starting on %d machines for evidence %s" % (
            len(evidence.machine_ids), evidence.sha256))

        # iterating machines which contains given evidence
        for machine_id in evidence.machine_ids:

            self.log.info(
                "Stop and Quarantine file job starting on machine %s for evidence %s" % (machine_id, evidence.sha256))

            # building request url with necessary endpoint and machine_id
            request_url = self.config.API.URL + "/api/machines/%s/StopAndQuarantineFile" % machine_id

            # set timeout_count for machine availability checks
            timeout_count = 0

            # set jos status flag for while loop
            is_job_pending = True

            # loop until machine action timeout exceeded or job finished/failed
            while self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP > timeout_count and is_job_pending:

                # check if machine is available
                if self.is_machine_available(machine_id):

                    # try-except block for handling api request exceptions
                    try:

                        # building isolation request body as dict
                        request_data = {
                            "Comment": self.config.MACHINE_ACTION.ANTI_VIRUS_SCAN.COMMENT,
                            "Sha1": evidence.sha1
                        }

                        # making api call loading response as json
                        response = requests.post(request_url, data=json.dumps(request_data), headers=self.headers)
                        json_response = json.loads(response.content)

                        # if api response contains the "error" key, should be an error about request
                        if "error" in json_response:
                            self.log.error("Failed to stop and quarantine evidence %s on machine %s - Error: %s" % (
                                evidence.sha256, machine_id, json_response["error"]["message"]))
                            is_job_pending = False
                        else:
                            self.log.info("Stop and quarantine job started for evidence %s on machine %s" % (
                                evidence.sha256, machine_id))
                            is_job_pending = False

                    except Exception as err:
                        self.log.error("Failed to stop and quarantine evidence %s on machine %s - Error: %s" % (
                            evidence.sha256, machine_id, err))
                        is_job_pending = False
                else:
                    # increment timeout counter for timeout check
                    timeout_count += 1

                    # sleep and wait pending machine actions to finish
                    time.sleep(self.config.MACHINE_ACTION.SLEEP)

            # if timeout exceeded, machine action job has failed
            if self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP <= timeout_count:
                error_message = "Machine was not available during the timeout (%s seconds)" % self.config.MACHINE_ACTION.MACHINE_TIMEOUT
                self.log.error("Failed to stop and quarantine evidence %s on machine %s - Error: %s" % (
                    evidence.sha256, machine_id, error_message))
            # else wait successful machine action job to finish
            else:
                time.sleep(self.config.MACHINE_ACTION.SLEEP)

    def isolate_machine(self, evidence):
        """
        Isolate machines for given evidence
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine
        :param evidence: evidence object
        :exception: when isolation failed
        :return void:
        """

        self.log.info("Isolating %d machines" % len(evidence.machine_ids))

        # iterating machines which contains given evidence
        for machine_id in evidence.machine_ids:

            self.log.info("Isolating machine %s" % machine_id)

            # building request url with necessary endpoint and machine_id
            request_url = self.config.API.URL + "/api/machines/%s/isolate" % machine_id

            # set timeout_count for machine availability checks
            timeout_count = 0

            # set jos status flag for while loop
            is_job_pending = True

            # loop until machine action timeout exceeded or job finished/failed
            while self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP > timeout_count and is_job_pending:

                # check if machine available
                if self.is_machine_available(machine_id):

                    # try-except block for handling api request exceptions
                    try:

                        # building isolation request body as dict
                        request_data = {
                            "Comment": self.config.MACHINE_ACTION.ISOLATION.COMMENT,
                            "IsolationType": self.config.MACHINE_ACTION.ISOLATION.TYPE
                        }

                        # making api call loading response as json
                        response = requests.post(request_url, data=json.dumps(request_data), headers=self.headers)
                        json_response = json.loads(response.content)

                        # if api response contains the "error" key, should be an error about request
                        if "error" in json_response:
                            self.log.error("Failed to isolate machine %s - Error: %s" % (
                                machine_id, json_response["error"]["message"]))
                            is_job_pending = False
                        else:
                            self.log.info("Machine %s isolation job started" % machine_id)
                            is_job_pending = False

                    except Exception as err:
                        self.log.error("Failed to isolate machine %s - Error: %s" % (machine_id, err))
                        is_job_pending = False
                else:
                    # increment timeout counter for timeout check
                    timeout_count += 1

                    # sleep and wait pending machine actions to finish
                    time.sleep(self.config.MACHINE_ACTION.SLEEP)

            # if timeout exceeded, machine action job has failed
            if self.config.MACHINE_ACTION.MACHINE_TIMEOUT / self.config.MACHINE_ACTION.SLEEP <= timeout_count:
                error_message = "Machine was not available during the timeout (%s seconds)" % self.config.MACHINE_ACTION.MACHINE_TIMEOUT
                self.log.error("Failed to isolate machine %s - Error: %s" % (machine_id, error_message))
            # else wait successful machine action job to finish
            else:
                time.sleep(self.config.MACHINE_ACTION.SLEEP)

    def run_automated_machine_actions(self, sample_data, evidence):
        """
        Running automated machine actions based on confiuration and VMRay Analyzer results
        :param sample_data: VMRay response for submitted sample
        :param evidence: evidence object
        :return void:
        """

        # Collecting investigation package from affected machines if configuration is active and verdict is selected
        if self.config.MACHINE_ACTION.COLLECT_INVESTIGATION_PACKAGE.ACTIVE and \
                sample_data["sample_verdict"] in self.config.MACHINE_ACTION.COLLECT_INVESTIGATION_PACKAGE.VERDICTS:
            self.collect_investigation_package(evidence)

        # Running antivirus scan on affected machines if configuration is active and verdict is selected
        if self.config.MACHINE_ACTION.ANTI_VIRUS_SCAN.ACTIVE and \
                sample_data["sample_verdict"] in self.config.MACHINE_ACTION.ANTI_VIRUS_SCAN.VERDICTS:
            self.run_antivirus_scan(evidence)

        # Stop and quarantine file in affected machines if configuration is active and verdict is selected
        if self.config.MACHINE_ACTION.STOP_AND_QUARANTINE_FILE.ACTIVE and \
                sample_data["sample_verdict"] in self.config.MACHINE_ACTION.STOP_AND_QUARANTINE_FILE.VERDICTS:
            self.stop_and_quarantine_file(evidence)

        # Isolate affected machines if configuration is active and verdict is selected
        if self.config.MACHINE_ACTION.ISOLATION.ACTIVE and \
                sample_data["sample_verdict"] in self.config.MACHINE_ACTION.ISOLATION.VERDICTS:
            self.isolate_machine(evidence)
