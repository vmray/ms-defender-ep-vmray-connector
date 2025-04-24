import io
import time
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from vmray.rest_api import VMRayRESTAPI
from app.config.conf import VMRayConfig, GeneralConfig, JOB_STATUS


class VMRay:
    """
    Wrapper class for VMRayRESTAPI modules and functions.
    Import this class to submit samples and retrieve reports.
    """

    def __init__(self, log):
        """
        Initialize, authenticate and healthcheck the VMRay instance, use VMRayConfig as configuration
        :param log: logger instance
        :return void
        """
        self.api = None
        self.log = log
        self.config = VMRayConfig

        self.authenticate()
        self.healthcheck()

    def healthcheck(self):
        """
        Healthcheck for VMRay REST API, uses system_info endpoint with improved stability.
        :param self.config.VMRAY_MAX_RETRY: Maximum number of retries in case of failure.
        :param self.config.VMRAY_RETRY_DELAY: Time to wait before retrying (in seconds).
        :raise: Exception when healthcheck fails after all retries.
        :return: boolean status of VMRay REST API
        """
        method = "GET"
        url = "/rest/system_info"

        for attempt in range(1, self.config.VMRAY_MAX_RETRY + 1):
            try:
                response = self.api.call(method, url)

                self.log.debug(
                    "Attempt %d/%d - Raw response: %s",
                    attempt,
                    self.config.VMRAY_MAX_RETRY,
                    response,
                )

                if isinstance(response, dict):
                    if (
                        "version" in response
                    ):  # Checking for a key that confirms successful response
                        self.log.info("VMRay Healthcheck successful")

                        return True
                    else:
                        self.log.error(
                            "Attempt %d/%d - Unexpected response format: %s",
                            attempt,
                            self.config.VMRAY_MAX_RETRY,
                            response,
                        )
                        break  # Stop retries for unexpected response format

                self.log.error(
                    "Attempt %d/%d - Invalid response type: %s",
                    attempt,
                    self.config.VMRAY_MAX_RETRY,
                    type(response),
                )
                break  # Stop retries if the response is of an unknown type
            except Exception as err:
                self.log.error(
                    "Attempt %d/%d - Healthcheck failed due to error: %s",
                    attempt,
                    self.config.VMRAY_MAX_RETRY,
                    err,
                )
                if (
                    "device not connected" in str(err).lower()
                    or "active live response session" in str(err).lower()
                ):
                    self.log.error("Non-recoverable error detected. Aborting retries.")
                    break

            if attempt < self.config.VMRAY_MAX_RETRY:
                self.log.info(
                    "Retrying healthcheck in %d seconds (Attempt %d/%d)...",
                    self.config.VMRAY_RETRY_DELAY,
                    attempt + 1,
                    self.config.VMRAY_MAX_RETRY,
                )
                time.sleep(self.config.VMRAY_RETRY_DELAY)

        self.log.error(
            f"Healthcheck failed after {self.config.VMRAY_MAX_RETRY} attempts"
        )
        raise Exception(
            "VMRAY Healthcheck failed after multiple attempts. Check logs for details."
        )

    def authenticate(self):
        """
        Authenticate the VMRay REST API
        :raise: When API Key is not properly configured
        :return: void
        """
        try:
            self.api = VMRayRESTAPI(
                self.config.URL,
                self.config.API_KEY,
                self.config.SSL_VERIFY,
                self.config.CONNECTOR_NAME,
            )
            self.log.debug(
                "Successfully authenticated the VMRay %s API" % self.config.API_KEY_TYPE
            )
        except Exception as err:
            self.log.error(err)
            raise

    def get_sample(self, identifier, sample_id=False):
        """
        Retrieve sample summary from VMRay database with sample_id or sha256 hash value
        :param identifier: sample_id or sha256 hash value to identify submitted sample
        :param sample_id: boolean value to determine which value (sample_id or sha256) is passed to function
        :return: dict object which contains summary data about sample
        """
        method = "GET"
        if sample_id:
            url = "/rest/sample/" + str(identifier)
        else:
            url = "/rest/sample/sha256/" + identifier

        try:
            response = self.api.call(method, url)
            if len(response) == 0:
                self.log.debug(
                    "Sample %s couldn't find in VMRay database." % (identifier)
                )
                return None
            else:
                self.log.debug("Sample %s retrieved from VMRay" % identifier)
                return response
        except Exception as err:
            self.log.debug(
                "Sample %s couldn't find in VMRay database. Error: %s"
                % (identifier, err)
            )
            return None

    def get_sample_iocs(self, sample_data):
        """
        Retrieve IOC values from VMRay
        :param sample_data: dict object which contains summary data about the sample
        :return iocs: dict object which contains IOC values according to the verdict
        """
        sample_id = sample_data["sample_id"]

        method = "GET"
        url = "/rest/sample/%s/iocs/verdict/%s"

        iocs = {}

        for key in GeneralConfig.INDICATOR_VERDICTS:
            try:
                response = self.api.call(method, url % (sample_id, key))
                iocs[key] = response
                self.log.debug("IOC reports for %s retrieved from VMRay" % sample_id)
            except Exception as err:
                self.log.error(err)
        return iocs

    def get_sample_vtis(self, sample_id):
        """
        Retrieve VTI's (VMRay Threat Identifier) values about the sample
        :param sample_id: id value of the sample
        :return: dict object which contains VTI information about the sample
        """
        method = "GET"
        url = "/rest/sample/%s/vtis" % str(sample_id)

        try:
            response = self.api.call(method, url)
            self.log.debug(
                "Sample %s VTI's successfully retrieved from VMRay" % sample_id
            )
            return response
        except Exception as err:
            self.log.debug(
                "Sample %s VTI's couldn't retrieved from VMRay database. Error: %s"
                % (sample_id, err)
            )
            return None

    def get_submission_analyses(self, submission_id):
        """
        Retrieve analyses details of submission to detect errors
        :param submission_id: id value of the submission
        :return: dict object which contains analysis information about the submission
        """
        method = "GET"
        url = "/rest/analysis/submission/%s" % str(submission_id)
        try:
            response = self.api.call(method, url)
            self.log.debug(
                "Submission %s analyses successfully retrieved from VMRay"
                % submission_id
            )
            return response
        except Exception as err:
            self.log.debug(
                "Submission %s analyses couldn't retrieved from VMRay. Error: %s"
                % (submission_id, err)
            )
            return None

    def parse_sample_data(self, sample):
        """
        Parse and extract summary data about the sample with keys below
        :param sample: dict object which contains raw data about the sample
        :return sample_data: dict objects which contains parsed data about the sample
        """
        sample_data = {}
        keys = [
            "sample_id",
            "sample_verdict",
            "sample_vti_score",
            "sample_severity",
            "sample_child_sample_ids",
            "sample_parent_sample_ids",
            "sample_md5hash",
            "sample_sha256hash",
            "sample_webif_url",
            "sample_classifications",
            "sample_threat_names",
        ]
        if sample is not None:
            if type(sample) == type([]):
                sample = sample[0]
            for key in keys:
                if key in sample:
                    sample_data[key] = sample[key]
        return sample_data

    def parse_sample_vtis(self, vtis):
        """
        Parse and extract VTI details about the sample with keys below
        :param vtis: dict object which contains raw VTI data about the sample
        :return parsed_vtis: dict object which contains parsed VTI data about the sample
        """
        parsed_vtis = []

        if vtis is not None:
            for vti in vtis["threat_indicators"]:
                parsed_vtis.append(
                    {
                        "category": vti["category"],
                        "classifications": vti["classifications"],
                        "operation": vti["operation"],
                    }
                )
        return parsed_vtis

    def parse_sample_iocs(self, iocs):
        """
        Parse and extract process, file and network IOC values about the sample
        :param iocs: dict object which contains raw IOC data about the sample
        :return ioc_data: dict object which contains parsed/extracted process, file and network IOC values
        """
        ioc_data = {}

        file_iocs = self.parse_file_iocs(iocs)
        network_iocs = self.parse_network_iocs(iocs)

        for key in file_iocs:
            ioc_data[key] = file_iocs[key]

        for key in network_iocs:
            ioc_data[key] = network_iocs[key]

        return ioc_data

    def parse_file_iocs(self, iocs):
        """
        Parse and extract File IOC values (sha256, file_name) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return file_iocs: dict object which contains sha256 hashes and file_names as IOC values
        """
        file_iocs = {}
        sha256 = set()
        md5 = set()
        sha1 = set()

        for ioc_type in iocs:
            files = iocs[ioc_type]["iocs"]["files"]
            for file in files:
                if file["verdict"] in GeneralConfig.INDICATOR_VERDICTS:
                    if "Ransomware" not in file["classifications"]:
                        for file_hash in file["hashes"]:
                            sha256.add(file_hash["sha256_hash"])
                            sha1.add(file_hash["sha1_hash"])
                            md5.add(file_hash["md5_hash"])

        file_iocs["sha256"] = sha256
        file_iocs["sha1"] = sha1
        file_iocs["md5"] = md5

        return file_iocs

    def parse_network_iocs(self, iocs):
        """
        Parse and extract Network IOC values (domain, IPV4) from the raw IOC dict
        :param iocs: dict object which contains raw IOC data about the sample
        :return network_iocs: dict object which contains domains and IPV4 addresses as IOC values
        """
        network_iocs = {}
        domains = set()
        ip_addresses = set()

        for ioc_type in iocs:
            ips = iocs[ioc_type]["iocs"]["ips"]
            for ip in ips:
                domains.update(ip["domains"])
                ip_addresses.add(ip["ip_address"])

            urls = iocs[ioc_type]["iocs"]["urls"]
            for url in urls:
                ip_addresses.update(url["ip_addresses"])
                for original_url in url["original_urls"]:
                    try:
                        ipaddress.ip_address(urlparse(original_url).netloc)
                        ip_addresses.add(urlparse(original_url).netloc)
                    except Exception as err:
                        domains.add(urlparse(original_url).netloc)

        network_iocs["domain"] = domains
        network_iocs["ipv4"] = ip_addresses

        return network_iocs

    def submit_samples(self, evidences):
        """
        Submit sample to VMRay Sandbox to analyze with retry mechanism.
        :param evidences: list of evidences which downloaded from Microsoft Defender for Endpoint
        :param max_retry: Maximum number of retries in case of failure
        :param retry_delay: Delay in seconds between retries
        :return submissions: dict object which contains submission_id and sample_id
        """
        method = "POST"
        url = "/rest/sample/submit"

        params = {}
        params["comment"] = self.config.SUBMISSION_COMMENT
        params["tags"] = ",".join(self.config.SUBMISSION_TAGS)
        params["user_config"] = """{"timeout":%d}""" % self.config.ANALYSIS_TIMEOUT

        submissions = []

        for evidence in evidences:
            retry_count = 0
            while retry_count <= self.config.VMRAY_MAX_RETRY:
                try:
                    with io.open(evidence.download_file_path, "rb") as file_object:
                        params["sample_file"] = file_object
                        response = self.api.call(method, url, params)

                        if len(response["errors"]) == 0:
                            submission_id = response["submissions"][0]["submission_id"]
                            sample_id = response["samples"][0]["sample_id"]
                            submissions.append(
                                {
                                    "submission_id": submission_id,
                                    "sample_id": sample_id,
                                    "sha256": evidence.sha256,
                                    "evidence": evidence,
                                }
                            )
                            self.log.debug(
                                f"File {evidence.download_file_path} submitted to VMRay"
                            )
                            break  # Exit retry loop on success
                        else:
                            for error in response["errors"]:
                                self.log.error(str(error))
                            break  # Exit retry loop if API returns errors
                except Exception as err:
                    self.log.error(f"Attempt {retry_count + 1} failed: {err}")
                    retry_count += 1
                    if retry_count > self.config.VMRAY_MAX_RETRY:
                        self.log.error(
                            f"Max retries reached for {evidence.download_file_path}"
                        )
                    else:
                        time.sleep(
                            self.config.VMRAY_RETRY_DELAY
                        )  # Wait before retrying

        self.log.info(f"{len(submissions)} files submitted to VMRay")
        return submissions

    def wait_submissions(self, submissions):
        """
        Wait for the submission analyses to finish
        :param submissions: list of submission dictionaries
        :return custom_dict : contains submission status, submission info and API response
        """

        method = "GET"
        url = "/rest/submission/%s"

        # Creating submission_objects list with submission info
        # Adding timestamp and error_count for checking status and timeouts
        submission_objects = []
        for submission in submissions:
            submission_objects.append(
                {
                    "submission_id": submission["submission_id"],
                    "evidence": submission["evidence"],
                    "sha256": submission["sha256"],
                    "sample_id": submission["sample_id"],
                    "timestamp": None,
                    "error_count": 0,
                }
            )

        self.log.info("Waiting %d submission jobs to finish" % len(submission_objects))

        # Wait for all submissions to finish or exceed timeout
        while len(submission_objects) > 0:
            time.sleep(VMRayConfig.ANALYSIS_JOB_TIMEOUT / 60)
            for submission_object in submission_objects:
                try:
                    response = self.api.call(
                        method, url % submission_object["submission_id"]
                    )

                    # If submission is finished, return submission info and process sample report,IOC etc
                    if response["submission_finished"]:
                        submission_objects.remove(submission_object)
                        self.log.info(
                            "Submission job %s finished"
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": True,
                            "response": response,
                            "submission": submission_object,
                        }

                    # If submission is not finished and timer is not set, start timer to check timeout
                    elif submission_object["timestamp"] is None:
                        if self.is_submission_started(
                            submission_object["submission_id"]
                        ):
                            submission_object["timestamp"] = datetime.now()

                    # If timer is set, check configured timeout and return status as not finished
                    elif (
                        datetime.now() - submission_object["timestamp"]
                    ).seconds >= VMRayConfig.ANALYSIS_JOB_TIMEOUT:
                        submission_objects.remove(submission_object)
                        self.log.error(
                            "Submission job %d exceeded the configured time threshold."
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": False,
                            "response": response,
                            "submission": submission_object,
                        }

                except Exception as err:
                    self.log.error(str(err).split(":")[0])

                    # If 5 errors are occured, return status as not finished else try again
                    if submission_object["error_count"] >= 5:
                        yield {
                            "finished": False,
                            "response": None,
                            "submission": submission_object,
                        }
                    else:
                        submission_object["error_count"] += 1

        self.log.info("Submission jobs finished")

    def is_submission_started(self, submission_id):
        """
        Check if submission jobs are started
        :param submission_id: id value of submission
        :return status: boolean value of status
        """

        method = "GET"
        url = "/rest/job/submission/%d"

        try:
            response = self.api.call(method, url % submission_id)
            self.log.debug(
                "Submission %d jobs successfully retrieved from VMRay" % submission_id
            )
            for job in response:
                if job["job_status"] == JOB_STATUS.INWORK:
                    self.log.debug(
                        "At least one job is started for submission %d" % submission_id
                    )
                    return True
            self.log.debug("No job has yet started for submission %d" % submission_id)
            return False
        except Exception as err:
            self.log.debug(
                "Submission %d jobs couldn't retrieved from VMRay. Error: %s"
                % (submission_id, err)
            )
            return False

    def check_submission_error(self, submission):
        """
        Check and log any analysis error in finished submissions
        :param submissions: list of submission_id's
        :return: void
        """
        analyses = self.get_submission_analyses(submission["submission_id"])
        if analyses is not None:
            for analysis in analyses:
                if analysis["analysis_severity"] == "error":
                    self.log.error(
                        "Analysis %d for submission %d has error: %s"
                        % (
                            analysis["analysis_id"],
                            submission["submission_id"],
                            analysis["analysis_result_str"],
                        )
                    )

    def get_sample_submissions(self, sample):
        sample_id = sample["sample_id"]

        method = "GET"
        url = "/rest/submission/sample/%s" % sample_id

        try:
            response = self.api.call(method, url)
            if len(response) == 0:
                self.log.debug(
                    "Sample %s couldn't find in VMRay database." % (sample_id)
                )
                return None
            else:
                self.log.debug("Sample %s retrieved from VMRay" % sample_id)
                return response
        except Exception as err:
            self.log.debug(
                "Sample %s couldn't find in VMRay database. Error: %s"
                % (sample_id, err)
            )
            return None

    def get_av_submissions(self, machines):
        for machine in machines:
            if len(machine.av_evidences) > 0:
                if machine.run_script_live_response_finished:
                    for evidence in machine.av_evidences.keys():
                        sample = self.get_sample(evidence, sample_id=False)
                        if sample is not None:
                            sample_data = self.parse_sample_data(sample)
                            submissions = self.get_sample_submissions(sample_data)
                            if submissions is not None:
                                for submission in submissions:
                                    if (
                                        "SubmittedFromEndpoint"
                                        in submission["submission_tags"]
                                    ):
                                        machine.av_evidences[
                                            evidence
                                        ].submissions.append(
                                            {
                                                "submission_id": submission[
                                                    "submission_id"
                                                ],
                                                "evidence": machine.av_evidences[
                                                    evidence
                                                ],
                                                "sha256": evidence,
                                                "sample_id": sample_data["sample_id"],
                                                "timestamp": None,
                                                "error_count": 0,
                                            }
                                        )
        return machines

    def wait_av_submissions(self, submissions):
        """
        Wait for the submission analyses to finish
        :param submissions: list of submission dictionaries
        :return custom_dict : contains submission status, submission info and API response
        """

        method = "GET"
        url = "/rest/submission/%s"

        # Creating submission_objects list with submission info
        # Adding timestamp and error_count for checking status and timeouts
        submission_objects = []
        for submission in submissions:
            submission_objects.append(
                {
                    "submission_id": submission["submission_id"],
                    "evidence": submission["evidence"],
                    "sha256": submission["sha256"],
                    "sample_id": submission["sample_id"],
                    "timestamp": None,
                    "error_count": 0,
                }
            )

        self.log.info("Waiting %d submission jobs to finish" % len(submission_objects))

        # Wait for all submissions to finish or exceed timeout
        while len(submission_objects) > 0:
            time.sleep(VMRayConfig.ANALYSIS_JOB_TIMEOUT / 60)
            for submission_object in submission_objects:
                try:
                    response = self.api.call(
                        method, url % submission_object["submission_id"]
                    )

                    # If submission is finished, return submission info and process sample report,IOC etc
                    if response["submission_finished"]:
                        submission_objects.remove(submission_object)
                        self.log.info(
                            "Submission job %s finished"
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": True,
                            "response": response,
                            "submission": submission_object,
                        }

                    # If submission is not finished and timer is not set, start timer to check timeout
                    elif submission_object["timestamp"] is None:
                        if self.is_submission_started(
                            submission_object["submission_id"]
                        ):
                            submission_object["timestamp"] = datetime.now()

                    # If timer is set, check configured timeout and return status as not finished
                    elif (
                        datetime.now() - submission_object["timestamp"]
                    ).seconds >= VMRayConfig.ANALYSIS_JOB_TIMEOUT:
                        submission_objects.remove(submission_object)
                        self.log.error(
                            "Submission job %d exceeded the configured time threshold."
                            % submission_object["submission_id"]
                        )
                        yield {
                            "finished": False,
                            "response": response,
                            "submission": submission_object,
                        }

                except Exception as err:
                    self.log.error(str(err).split(":")[0])

                    # If 5 errors are occured, return status as not finished else try again
                    if submission_object["error_count"] >= 5:
                        yield {
                            "finished": False,
                            "response": None,
                            "submission": submission_object,
                        }
                    else:
                        submission_object["error_count"] += 1

        self.log.info("Submission jobs finished")

    def submit_av_samples(self, file_objects):
        """
        Submit files to the antivirus system for scanning or analysis.

        Args:
            file_objects (list): A list of file objects to be submitted for VMRay scanning.
            self.config.VMRAY_MAX_RETRY (int): Maximum number of retries for failed API calls.
            self.config.VMRAY_RETRY_DELAY (int): Initial delay between retries in seconds.

        Returns:
            None
        """
        params = {}
        params["comment"] = self.config.SUBMISSION_COMMENT
        params["tags"] = ",".join(self.config.SUBMISSION_AV_TAGS)
        params["user_config"] = """{"timeout":%d}""" % self.config.ANALYSIS_TIMEOUT
        method = "POST"

        url = "/rest/sample/submit"
        submissions = []

        for file_obj in file_objects:
            try:
                for hash, file in file_obj.items():
                    params["sample_file"] = file
                    attempts = 0

                    while attempts <= self.config.VMRAY_MAX_RETRY:
                        try:
                            response = self.api.call(method, url, params)
                            if response and not response.get("errors"):
                                submission_id = response["submissions"][0][
                                    "submission_id"
                                ]
                                sample_id = response["samples"][0]["sample_id"]
                                submissions.append(
                                    {
                                        "submission_id": submission_id,
                                        "sample_id": sample_id,
                                        "sha256": hash,
                                    }
                                )
                                self.log.info(
                                    f"Submission ID {submission_id} and Sample ID {sample_id}"
                                )
                                break  # Exit retry loop on success
                            else:
                                errors = response.get("errors", [])
                                for error in errors:
                                    self.log.error(f"Error: {error}")
                                raise Exception(
                                    "API returned errors, retrying..."
                                )  # Trigger retry logic

                        except Exception as err:
                            attempts += 1
                            if attempts > self.config.VMRAY_MAX_RETRY:
                                self.log.error(
                                    f"Max retries reached for {hash}. Error: {err}"
                                )
                                break
                            else:
                                self.log.warning(
                                    f"Retry {attempts}/{self.config.VMRAY_MAX_RETRY} for {hash}. Retrying in {self.config.VMRAY_RETRY_DELAY} seconds..."
                                )
                                time.sleep(self.config.VMRAY_RETRY_DELAY)
                                self.config.VMRAY_RETRY_DELAY *= (
                                    2  # Exponential backoff
                                )

            except Exception as err:
                self.log.error(f"Unexpected error: {err}")
