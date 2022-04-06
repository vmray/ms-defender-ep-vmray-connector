import logging as log
import os
import time
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

from app.lib.MicrosoftDefender import MicrosoftDefender
from app.lib.VMRay import VMRay
from app.lib.Models import Machine

from app.config.conf import GeneralConfig, MicrosoftDefenderConfig, DatabaseConfig, RUNTIME_MODE


def group_evidences_by_machines(evidences):
    """
    Helper function to group evidences by machine
    :param evidences: dict of evidence objects
    :return machines: list of machine objects which contains related evidences
    """
    machines = {}

    # iterating only evidence objects of evidences dict
    for evidence in evidences.values():
        # select first machine for live response
        # other machine_ids are used for remediation actions like isolation, av_scan etc
        selected_machine_id = list(evidence.machines)[0]

        # if machine object already created and added to the dict, update the evidences
        if selected_machine_id in machines.keys():
            machines[selected_machine_id].evidences.append(evidence)
        # otherwise create machine object, append evidence and add it to the dict
        else:
            machine = Machine(selected_machine_id)
            machine.evidences.append(evidence)
            machines[selected_machine_id] = machine
    return list(machines.values())


def run():
    if not GeneralConfig.LOG_DIR.exists():
        GeneralConfig.LOG_DIR.mkdir()

    if not GeneralConfig.LOG_FILE_PATH.exists():
        GeneralConfig.LOG_FILE_PATH.touch()

    if not MicrosoftDefenderConfig.DOWNLOAD.DIR.exists():
        MicrosoftDefenderConfig.DOWNLOAD.ABSOLUTE_PATH.mkdir()

    if not DatabaseConfig.DB_DIR.exists():
        DatabaseConfig.DB_PATH.mkdir()

    # Configure logging
    log.basicConfig(filename=GeneralConfig.LOG_FILE_PATH,
                    format='[%(asctime)s] [<pid:%(process)d> %(filename)s:%(lineno)s %(funcName)s] %(levelname)s %(message)s',
                    level=GeneralConfig.LOG_LEVEL)
    log.info('[CONNECTOR.PY] Started VMRAY Analyzer Connector for Microsoft Defender for Endpoint')

    # Initializing and authenticating api instances
    md = MicrosoftDefender(log)
    vmray = VMRay(log)

    # Dict of evidences which found on VMRay database
    found_evidences = {}

    # Dict of evidences which need to be downloaded from Microsoft Defender for Endpoint
    download_evidences = {}

    # Retrieving evidences from Microsoft Defender for Endpoint
    evidences = md.get_evidences_from_alerts()

    # Checking hash values in VMRay database, if evidence is found on VMRay no need to submit again
    for sha256 in evidences:
        sample = vmray.get_sample(sha256)
        if sample is not None:
            # if evidence found on VMRay we need store sample metadata in Evidence object
            evidences[sha256].vmray_sample = sample
            found_evidences[sha256] = evidences[sha256]
        else:
            download_evidences[sha256] = evidences[sha256]

    log.info("%d evidences found on VMRay database" % len(found_evidences))
    log.info("%d evidences need to be downloaded and submitted" % len(download_evidences))

    # Retrieving indicators from Microsoft Defender for Endpoint to check duplicates
    old_indicators = md.get_indicators()

    # Retrieving indicators from VMRay Analyzer for found evidences
    for sha256 in found_evidences:
        evidence = found_evidences[sha256]

        sample_data = vmray.parse_sample_data(evidence.vmray_sample)

        # If sample identified as suspicious or malicious we need to extract indicator values and import them to Microsoft Defender for Endpoint
        if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:
            # Retrieving and parsing indicators
            sample_iocs = vmray.get_sample_iocs(sample_data)
            ioc_data = vmray.parse_sample_iocs(sample_iocs)

            # Creating Indicator objects with checking old_indicators for duplicates
            indicator_objects = md.create_indicator_objects(ioc_data, old_indicators)

            # Submitting new indicators to Microsoft Defender for Endpoint
            md.submit_indicators(indicator_objects)

            # Retrieving and parsing sample vtis from VMRay Analyzer
            vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
            sample_vtis = vmray.parse_sample_vtis(vti_data)

            # Enriching alerts with vtis and sample metadata
            md.enrich_alerts(evidence, sample_data, sample_vtis)

            # Running automated remediation actions based on configuration
            md.run_automated_machine_actions(sample_data, evidence)

    # Group evidences by machines for gathering evidence files with live response
    machines = group_evidences_by_machines(download_evidences)
    log.info("%d machines contains evidences" % len(machines))

    # Running live response job for gathering evidence files from machines
    machines = md.run_live_response(machines)

    # Collect evidence objects which successful live response jobs and download url
    successful_evidences = [evidence for machine in machines for evidence in machine.get_successful_evidences()]

    # Download evidence files from Microsoft Defender for Endpoint
    downloaded_evidences = md.download_evidences(successful_evidences)
    log.info("%d evidence file downloaded successfully" % len(downloaded_evidences))

    # Retrieving indicators from Microsoft Defender for Endpoint to check duplicates
    old_indicators = md.get_indicators()

    # Submitting downloaded samples to VMRay
    submissions = vmray.submit_samples(downloaded_evidences)

    # Waiting and processing submissions
    for result in vmray.wait_submissions(submissions):
        submission = result["submission"]
        evidence = submission["evidence"]
        vmray.check_submission_error(submission)

        if result["finished"]:
            sample = vmray.get_sample(submission["sample_id"], True)
            sample_data = vmray.parse_sample_data(sample)

            # If sample identified as suspicious or malicious we need to extract IOC values and import them to Microsoft Defender for Endpoint
            if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:
                # Retrieving and parsing indicators
                sample_iocs = vmray.get_sample_iocs(sample_data)
                ioc_data = vmray.parse_sample_iocs(sample_iocs)

                # Creating Indicator objects with checking old_indicators for duplicates
                indicator_objects = md.create_indicator_objects(ioc_data, old_indicators)

                # Submitting new indicators to Microsoft Defender for Endpoint
                md.submit_indicators(indicator_objects)

                # Retrieving and parsing sample vtis from VMRay Analyzer
                vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                sample_vtis = vmray.parse_sample_vtis(vti_data)

                # Enriching alerts with vtis and sample metadata
                md.enrich_alerts(evidence, sample_data, sample_vtis)

                # Running automated remediation actions based on configuration
                md.run_automated_machine_actions(sample_data, evidence)

    # Removing downloaded files
    for downloaded_evidence in downloaded_evidences:
        os.remove(downloaded_evidence.download_file_path)


if __name__ == "__main__":
    if GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.DOCKER:
        while True:
            run()
            log.info("Sleeping %d seconds." % GeneralConfig.TIME_SPAN)
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()
