import logging as log
import os
import time
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

from app.config.conf import GeneralConfig, MicrosoftDefenderConfig, VMRayConfig, DatabaseConfig, RUNTIME_MODE, \
    ALERT_DETECTION_SOURCE
from app.lib.Database import Database
from app.lib.MicrosoftDefender import MicrosoftDefender
from app.lib.VMRay import VMRay
from app.lib.Models import Machine


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
        selected_machine_id = list(evidence.machine_ids)[0]

        # if machine object already created and added to the dict, update the evidences
        if selected_machine_id in machines.keys():

            if evidence.detection_source == ALERT_DETECTION_SOURCE.WINDOWS_DEFENDER_AV:
                machines[selected_machine_id].av_evidences[evidence.sha256] = evidence
            else:
                machines[selected_machine_id].edr_evidences[evidence.sha256] = evidence

        # otherwise create machine object, append evidence and add it to the dict
        else:
            machine = Machine(selected_machine_id)

            if evidence.detection_source == ALERT_DETECTION_SOURCE.WINDOWS_DEFENDER_AV:
                machine.av_evidences[evidence.sha256] = evidence
            else:
                machine.edr_evidences[evidence.sha256] = evidence

            machines[selected_machine_id] = machine
    return list(machines.values())


def update_evidence_machine_ids(machines):
    evidences_by_machine = {}

    for machine in machines:

        for evidence in machine.edr_evidences.values():
            if evidence.sha256 in evidences_by_machine:
                evidences_by_machine[evidence.sha256].add(machine.id)
            else:
                evidences_by_machine[evidence.sha256] = {machine.id}

        for evidence in machine.av_evidences.values():
            if evidence.sha256 in evidences_by_machine:
                evidences_by_machine[evidence.sha256].add(machine.id)
            else:
                evidences_by_machine[evidence.sha256] = {machine.id}

    for machine in machines:
        for evidence in machine.edr_evidences.values():
            evidence.machine_ids = evidences_by_machine[evidence.sha256]

        for evidence in machine.av_evidences.values():
            evidence.machine_ids = evidences_by_machine[evidence.sha256]

    return machines


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

    # Initializing db instance
    db = Database(log)

    # Initializing and authenticating api instances
    md = MicrosoftDefender(log, db)

    vmray = VMRay(log)

    # Dict of evidences which found on VMRay database
    found_evidences = {}

    # Dict of evidences which need to be downloaded from Microsoft Defender for Endpoint
    download_evidences = {}

    # Dict of evidences which found on VMRay database but will be resubmitted
    resubmit_evidences = {}

    # Retrieving alerts from Microsoft Defender for Endpoint
    evidences = md.get_evidences()

    # Checking hash values in VMRay database, if evidence is found on VMRay no need to submit again
    for sha256 in evidences:
        sample = vmray.get_sample(sha256)
        if sample is not None:
            # If resubmission is active and evidence verdict in configured resubmission verdicts
            # Evidence added into resubmit evidences and re-analyzed
            evidence_metadata = vmray.parse_sample_data(sample)

            if VMRayConfig.RESUBMIT and evidence_metadata["sample_verdict"] in VMRayConfig.RESUBMISSION_VERDICTS:
                log.debug(
                    "File %s found in VMRay database, but will be resubmitted." % sha256)
                resubmit_evidences[sha256] = evidences[sha256]
            else:
                log.debug(
                    "File %s found in VMRay database. No need to submit again." % sha256)
                # if evidence found on VMRay we need store sample metadata in Evidence object
                evidences[sha256].vmray_sample = sample
                found_evidences[sha256] = evidences[sha256]
        else:
            download_evidences[sha256] = evidences[sha256]

    if len(found_evidences) > 0:
        log.info("%d evidences found on VMRay" % len(found_evidences))

    if len(resubmit_evidences) > 0:
        log.info("%d evidences found on VMRay, but will be resubmitted." % len(resubmit_evidences))

    # Combine download_evidences dict and resubmit_evidences dict for submission
    download_evidences.update(resubmit_evidences)

    if len(download_evidences) > 0:
        log.info("%d evidences need to be downloaded and submitted" % len(download_evidences))

    if md.config.INDICATOR.ACTIVE:
        # Retrieving indicators from Microsoft Defender for Endpoint to check duplicates
        old_indicators = md.get_indicators()

    # Retrieving indicators from VMRay Analyzer for found evidences
    for evidence in found_evidences.values():

        sample_data = vmray.parse_sample_data(evidence.vmray_sample)

        # If sample identified as suspicious or malicious we need to extract indicator values and import them to Microsoft Defender for Endpoint
        if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:

            if md.config.INDICATOR.ACTIVE:
                # Retrieving and parsing indicators
                sample_iocs = vmray.get_sample_iocs(sample_data)
                ioc_data = vmray.parse_sample_iocs(sample_iocs)

                # Creating Indicator objects with checking old_indicators for duplicates
                indicator_objects = md.create_indicator_objects(ioc_data, old_indicators)

                # Submitting new indicators to Microsoft Defender for Endpoint
                md.submit_indicators(indicator_objects)

            if md.config.ENRICHMENT.ACTIVE:
                # Retrieving and parsing sample vtis from VMRay Analyzer
                vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                sample_vtis = vmray.parse_sample_vtis(vti_data)

                # Enriching alerts with vtis and sample metadata
                md.enrich_alerts(evidence, sample_data, sample_vtis)

            # Running automated remediation actions based on configuration
            md.run_automated_machine_actions(sample_data, evidence)

    # Group evidences by machines for gathering evidence files with live response
    machines = group_evidences_by_machines(evidences)

    # Update evidence machine ids to process multiple evidences in different machines
    machines = update_evidence_machine_ids(machines)
    log.info("%d machines contains evidences" % len(machines))

    # Running live response job for gathering evidence files from machines
    machines = md.run_edr_live_response(machines)

    # Collect evidence objects which successful live response jobs and download url
    successful_evidences = [evidence for machine in machines for evidence in machine.get_successful_edr_evidences()]
    log.info("%d evidences successfully collected with live response" % len(successful_evidences))

    # Download evidence files from Microsoft Defender for Endpoint
    downloaded_evidences = md.download_evidences(successful_evidences)
    log.info("%d evidence file downloaded successfully" % len(downloaded_evidences))

    # Insert downloaded evidences to database
    for evidence in downloaded_evidences:
        for machine_id in evidence.machine_ids:
            for alert_id in evidence.alert_ids:
                db.insert_evidence(machine_id=machine_id,
                                   alert_id=alert_id,
                                   evidence_sha256=evidence.sha256)

    if md.config.INDICATOR.ACTIVE:
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

                if md.config.INDICATOR.ACTIVE:
                    # Retrieving and parsing indicators
                    sample_iocs = vmray.get_sample_iocs(sample_data)
                    ioc_data = vmray.parse_sample_iocs(sample_iocs)

                    # Creating Indicator objects with checking old_indicators for duplicates
                    indicator_objects = md.create_indicator_objects(ioc_data, old_indicators)

                    # Submitting new indicators to Microsoft Defender for Endpoint
                    md.submit_indicators(indicator_objects)

                if md.config.ENRICHMENT.ACTIVE:
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
