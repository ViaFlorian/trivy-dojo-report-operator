import json
import logging
import os
import shutil
import subprocess
import threading
import time
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from kopf.testing import KopfRunner

# configure logging for test diagnostics
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s")

# module-level logger
logger = logging.getLogger(__name__)


# Global list to track reimport-scan requests
reimport_scan_requests = []
request_counter = 0


@pytest.fixture(autouse=True)
def cleanup_debug_dir():
    """Clean up debug directory before every test execution."""
    debug_dir = os.path.join("tests", "debug")
    if os.path.isdir(debug_dir):
        shutil.rmtree(debug_dir)
    yield


def write_request_debug(form_data, content_type):
    """Write request form_data to a debug file for analysis."""
    global request_counter
    debug_dir = os.path.join("tests", "debug")
    os.makedirs(debug_dir, exist_ok=True)

    debug_file = os.path.join(debug_dir, f"request_{request_counter:03d}.json")
    debug_data = {
        "content_type": content_type,
        "form_data": form_data
    }

    if form_data.get("file"):
        try:
            file_content = form_data["file"]
            if isinstance(file_content, str):
                file_content = json.loads(file_content)
            # replace with parsed content for easier analysis
            form_data["file"] = file_content
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing file content: {e}")

    with open(debug_file, 'w') as f:
        json.dump(debug_data, f, indent=2)

    request_counter += 1


def parse_multipart_form_data(body_bytes, content_type):
    """Parse multipart form data from request body."""
    form_data = {}
    # Construct a full email message with headers
    full_message = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + \
        body_bytes
    msg = BytesParser().parsebytes(full_message)

    # Get all parts of the multipart message
    if msg.is_multipart():
        for part in msg.get_payload():
            name = part.get_param('name', header='content-disposition')
            if name:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8')
                form_data[name] = payload

    return form_data


class _DefectDojoMockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/v2/reimport-scan/":
            # read and capture body
            length = int(self.headers.get("Content-Length", 0))
            body_bytes = b""
            if length:
                body_bytes = self.rfile.read(length)

            # Store the request body and content type for verification
            content_type = self.headers.get("Content-Type", "")
            form_data = parse_multipart_form_data(body_bytes, content_type)
            reimport_scan_requests.append({
                "body": body_bytes,
                "content_type": content_type
            })

            # Write debug information to file
            write_request_debug(form_data, content_type)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{\"status\": \"ok\"}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return


def test_operator():
    global request_counter
    request_counter = 0

    # start a mock DefectDojo HTTP server on a random free port
    server = ThreadingHTTPServer(("localhost", 0), _DefectDojoMockHandler)
    port = server.server_address[1]
    os.environ.setdefault("DEFECT_DOJO_API_KEY", "test-api-key")
    os.environ.setdefault("DEFECT_DOJO_URL", f"http://localhost:{port}")
    os.environ.setdefault("DEFECT_DOJO_ACTIVE", "true")
    os.environ.setdefault("REPORTS", "vulnerabilityreports")
    os.environ.setdefault("DEFECT_DOJO_AUTO_CREATE_CONTEXT", "true")
    os.environ.setdefault("DEFECT_DOJO_CLOSE_OLD_FINDINGS", "true")
    os.environ.setdefault(
        "DEFECT_DOJO_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE", "true")
    os.environ.setdefault("DEFECT_DOJO_DEDUPLICATION_ON_ENGAGEMENT", "false")
    os.environ.setdefault("DEFECT_DOJO_DO_NOT_REACTIVATE", "false")
    os.environ.setdefault("DEFECT_DOJO_ENGAGEMENT_NAME",
                          "body['metadata']['namespace']")
    os.environ.setdefault("DEFECT_DOJO_EVAL_ENGAGEMENT_NAME", "true")
    os.environ.setdefault("DEFECT_DOJO_EVAL_SERVICE_NAME", "true")
    os.environ.setdefault("DEFECT_DOJO_SERVICE_NAME",
                          "f\"{body['metadata']['namespace']}/{body['metadata']['labels']['trivy-operator.resource.kind']}/{body['metadata']['labels']['trivy-operator.container.name']}\"")
    os.environ.setdefault("DEFECT_DOJO_ENV_NAME", "production")
    os.environ.setdefault("DEFECT_DOJO_EVAL_ENV_NAME", "false")
    os.environ.setdefault("DEFECT_DOJO_EVAL_PRODUCT_NAME", "false")
    os.environ.setdefault("DEFECT_DOJO_EVAL_PRODUCT_TYPE_NAME", "false")
    os.environ.setdefault("DEFECT_DOJO_EVAL_TEST_TITLE", "false")
    os.environ.setdefault("DEFECT_DOJO_MINIMUM_SEVERITY", "High")
    os.environ.setdefault("DEFECT_DOJO_PRODUCT_NAME", "Security-Platform")
    os.environ.setdefault("DEFECT_DOJO_PRODUCT_TYPE_NAME",
                          "Research and Development")
    os.environ.setdefault("DEFECT_DOJO_PUSH_TO_JIRA", "false")
    os.environ.setdefault("DEFECT_DOJO_TEST_TITLE", "Kubernetes")
    os.environ.setdefault("DEFECT_DOJO_VERIFIED", "false")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with KopfRunner(['run', '-A', '--verbose', 'src/handlers.py']) as runner:
            # do something while the operator is running.

            subprocess.run("kubectl apply -f tests/resources/simple_old_container_deployment.yaml",
                           shell=True, check=True)

            # Wait until vulnerability report is created
            timeout = 120
            start_time = time.time()
            while time.time() - start_time < timeout:
                result = subprocess.run("kubectl get vulnerabilityreports --all-namespaces",
                                        shell=True, capture_output=True, text=True)
                if result.stdout and "simple-alpine-deployment" in result.stdout:
                    break
                time.sleep(1)

            time.sleep(1)

            subprocess.run("kubectl delete -f tests/resources/simple_old_container_deployment.yaml",
                           shell=True, check=True)
            time.sleep(1)  # give it some time to react

        assert runner.exit_code == 0
        assert runner.exception is None

        # Verify reimport-scan was called exactly twice
        assert len(
            reimport_scan_requests) == 2, f"Expected 2 reimport-scan calls, got {len(reimport_scan_requests)}"

        # Parse the multipart form data from requests and verify contents
        for index, item in enumerate(reimport_scan_requests):
            form_data = parse_multipart_form_data(
                item["body"], item["content_type"])

            assert "service" in form_data, "Expected 'service' field in form data"
            assert form_data["service"] == "default/ReplicaSet/alpine-sleep"
            file_as_json = json.loads(form_data.get("file", "{}"))
            if index == 0:
                # First request should have findings
                assert "vulnerabilities" in file_as_json.get(
                    "report", {}), "Expected 'vulnerabilities' in file content for first request"
                assert len(
                    file_as_json["report"]["vulnerabilities"]) > 0, "Expected at least one vulnerability in first request"
            else:
                # Second request should have no findings
                assert "vulnerabilities" in file_as_json.get(
                    "report", {}), "Expected 'vulnerabilities' in file content for second request"
                assert len(
                    file_as_json["report"]["vulnerabilities"]) == 0, "Expected no vulnerabilities in second request"

    finally:
        # Clear the global list for next test run
        reimport_scan_requests.clear()
        server.shutdown()
        server.server_close()
