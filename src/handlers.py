import json
import os
from io import BytesIO

import kopf
import prometheus_client
import requests
from requests.exceptions import HTTPError

import settings

prometheus_client.start_http_server(9090)
REQUEST_TIME = prometheus_client.Summary(
    "request_processing_seconds", "Time spent processing request"
)
PROMETHEUS_DISABLE_CREATED_SERIES = True

c = prometheus_client.Counter("requests_total", "HTTP Requests", ["status"])

proxies = {
    "http": settings.HTTP_PROXY,
    "https": settings.HTTPS_PROXY,
} if settings.HTTP_PROXY or settings.HTTPS_PROXY else None


def check_allowed_reports(report: str):
    allowed_reports: list[str] = [
        "configauditreports",
        "vulnerabilityreports",
        "exposedsecretreports",
        "infraassessmentreports",
        "rbacassessmentreports",
    ]

    if report not in allowed_reports:
        print(
            f"[ERROR] report {report} is not allowed. Allowed reports: {allowed_reports}"
        )
        exit(1)


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """
    Configure kopf
    """

    # kopf randomly stops watching resources. setting timeouts is supposed to help.
    # see these issue for more info:
    # https://github.com/nolar/kopf/issues/957
    # https://github.com/nolar/kopf/issues/585
    # https://github.com/nolar/kopf/issues/955
    # see https://kopf.readthedocs.io/en/latest/configuration/#api-timeouts
    settings.watching.connect_timeout = 60
    settings.watching.server_timeout = 600
    settings.watching.client_timeout = 610

    # This function tells kopf to use the StatusDiffBaseStorage instead
    # of the annotations-based storage, because the annotation will get too large
    # for k8s to handle. see: https://github.com/kubernetes-sigs/kubebuilder/issues/2556
    settings.persistence.diffbase_storage = kopf.MultiDiffBaseStorage(
        [
            kopf.StatusDiffBaseStorage(
                field="status.diff-base",
                ignored_fields=["report.vulnerabilities"]
            ),
        ]
    )


def build_full_object(body: dict) -> dict:
    full_object = {}
    for key in body:
        full_object[key] = body[key]
    return full_object


def dump_debug(name: str, data: dict | None, report: dict | None) -> None:
    """Write debugging information to the tests directory so that tests can inspect it.

    The files are written under ``tests/debug`` and named with the provided
    ``name`` prefix. ``data`` corresponds to the payload sent to DefectDojo and
    ``report`` corresponds to the full object built from the k8s resource.
    Both are written as pretty-printed JSON.  The function is a no-op if the
    directory cannot be created for some reason (tests will still run).
    """
    try:
        os.makedirs("tests/debug", exist_ok=True)
        if data is not None:
            with open(os.path.join("tests/debug", f"{name}_data.json"), "w") as f:
                json.dump(data, f, indent=2)
        if report is not None:
            with open(os.path.join("tests/debug", f"{name}_report.json"), "w") as f:
                json.dump(report, f, indent=2)
    except Exception:
        # ignore any issues creating debug files; they are only for manual
        # inspection while debugging the operator.
        pass


def evaluate_if_needed(setting: str, eval_flag: bool, body) -> str:
    if eval_flag:
        assert body is not None, "body is required for eval"
        return eval(setting)
    else:
        return setting


def prepare_data(settings, body, isDeleteCallback) -> dict:
    _DEFECT_DOJO_ENGAGEMENT_NAME = evaluate_if_needed(
        settings.DEFECT_DOJO_ENGAGEMENT_NAME, settings.DEFECT_DOJO_EVAL_ENGAGEMENT_NAME, body)
    _DEFECT_DOJO_PRODUCT_NAME = evaluate_if_needed(
        settings.DEFECT_DOJO_PRODUCT_NAME, settings.DEFECT_DOJO_EVAL_PRODUCT_NAME, body)
    _DEFECT_DOJO_PRODUCT_TYPE_NAME = evaluate_if_needed(
        settings.DEFECT_DOJO_PRODUCT_TYPE_NAME, settings.DEFECT_DOJO_EVAL_PRODUCT_TYPE_NAME, body)
    _DEFECT_DOJO_SERVICE_NAME = evaluate_if_needed(
        settings.DEFECT_DOJO_SERVICE_NAME, settings.DEFECT_DOJO_EVAL_SERVICE_NAME, body)
    _DEFECT_DOJO_ENV_NAME = evaluate_if_needed(
        settings.DEFECT_DOJO_ENV_NAME, settings.DEFECT_DOJO_EVAL_ENV_NAME, body)
    _DEFECT_DOJO_TEST_TITLE = evaluate_if_needed(
        settings.DEFECT_DOJO_TEST_TITLE, settings.DEFECT_DOJO_EVAL_TEST_TITLE, body)

    active = settings.DEFECT_DOJO_ACTIVE
    if isDeleteCallback:
        active = False

    data = {
        "active": active,
        "verified": settings.DEFECT_DOJO_VERIFIED,
        "close_old_findings": settings.DEFECT_DOJO_CLOSE_OLD_FINDINGS,
        "close_old_findings_product_scope": settings.DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE,
        "push_to_jira": settings.DEFECT_DOJO_PUSH_TO_JIRA,
        "minimum_severity": settings.DEFECT_DOJO_MINIMUM_SEVERITY,
        "auto_create_context": settings.DEFECT_DOJO_AUTO_CREATE_CONTEXT,
        "deduplication_on_engagement": settings.DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT,
        "scan_type": "Trivy Operator Scan",
        "engagement_name": _DEFECT_DOJO_ENGAGEMENT_NAME,
        "product_name": _DEFECT_DOJO_PRODUCT_NAME,
        "product_type_name": _DEFECT_DOJO_PRODUCT_TYPE_NAME,
        "service": _DEFECT_DOJO_SERVICE_NAME,
        "environment": _DEFECT_DOJO_ENV_NAME,
        "test_title": _DEFECT_DOJO_TEST_TITLE,
        "do_not_reactivate": settings.DEFECT_DOJO_DO_NOT_REACTIVATE,
    }
    return data


def create_report_file(full_object: dict) -> dict:
    json_string = json.dumps(full_object)
    json_file = BytesIO(json_string.encode("utf-8"))
    return {"file": ("report.json", json_file)}


def send_to_dojo_request(url: str, headers: dict, data: dict, files: dict, proxies: dict) -> requests.Response:
    response = requests.post(
        url, headers=headers, data=data, files=files, verify=True, proxies=proxies)
    return response


def get_headers(settings) -> dict:
    return {
        "Authorization": "Token " + settings.DEFECT_DOJO_API_KEY,
        "Accept": "application/json",
    }


def send_and_handle_response(url: str, headers: dict, data: dict, files: dict, proxies: dict, logger, kind: str, name: str) -> None:
    """Send data to DefectDojo and handle the response with retries and metric tracking.

    Args:
        url: DefectDojo API endpoint URL
        headers: HTTP headers including authorization
        data: Request payload data
        files: Files to send in the request
        proxies: HTTP proxy configuration
        logger: Kopf logger instance
        kind: Kubernetes resource kind (for logging)
        name: Kubernetes resource name (for logging)
    """
    try:
        response = send_to_dojo_request(url, headers, data, files, proxies)
        response.raise_for_status()
    except HTTPError as http_err:
        c.labels("failed").inc()
        raise kopf.TemporaryError(
            f"HTTP error occurred: {http_err} - {response.content}. Retrying in 60 seconds",
            delay=60,
        )
    except Exception as err:
        c.labels("failed").inc()
        raise kopf.TemporaryError(
            f"Other error occurred: {err}. Retrying in 60 seconds", delay=60
        )
    else:
        c.labels("success").inc()
        logger.info(f"Finished {kind} {name}")
        logger.debug(response.content)


labels: dict = {}
if settings.LABEL and settings.LABEL_VALUE:
    labels = {settings.LABEL: settings.LABEL_VALUE}
else:
    labels = {}

for report in settings.REPORTS:
    # check if reports are allowed
    check_allowed_reports(report)

    @REQUEST_TIME.time()
    @kopf.on.create(report.lower() + ".aquasecurity.github.io", labels=labels)
    def send_to_dojo(body, meta, logger, **_):
        """
        The main function that creates a report-file from the trivy-operator vulnerabilityreport
        and sends it to the defectdojo instance.
        """

        logger.info(f"Working on {body['kind']} {meta['name']}")

        full_object = build_full_object(body)

        logger.debug(full_object)

        data = prepare_data(settings, body, isDeleteCallback=False)

        logger.debug(data)

        report_file = create_report_file(full_object)

        # dump payloads for debugging/comparison purposes. tests can look at
        # ``tests/debug`` after running to compare create vs delete data.
        # dump_debug(f"send_{meta['name']}", data, full_object)

        send_and_handle_response(
            settings.DEFECT_DOJO_URL + "/api/v2/reimport-scan/",
            get_headers(settings),
            data,
            report_file,
            proxies,
            logger,
            body['kind'],
            meta['name'],
        )

    @REQUEST_TIME.time()
    @kopf.on.delete(report.lower() + ".aquasecurity.github.io", labels=labels)
    def handle_delete(body, meta, logger, **_):
        """
        Handle deletion of aquasecurity resources by deactivating findings in DefectDojo.
        """
        logger.info(f"Detected deletion of {body['kind']} {meta['name']}")

        full_object = build_full_object(body)

        logger.debug(full_object)

        data = prepare_data(settings, body, isDeleteCallback=True)

        logger.debug(data)

        # Remove vulnerabilities from the report before sending
        if 'report' in full_object and 'vulnerabilities' in full_object['report']:
            full_object['report']['vulnerabilities'] = list()

        report_file = create_report_file(full_object)

        # also persist debug output so we can compare against the create
        # handler later.
        # dump_debug(f"delete_{meta['name']}", data, full_object)

        send_and_handle_response(
            settings.DEFECT_DOJO_URL + "/api/v2/reimport-scan/",
            get_headers(settings),
            data,
            report_file,
            proxies,
            logger,
            body['kind'],
            meta['name'],
        )
