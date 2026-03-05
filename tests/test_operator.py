import json
import os
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from kopf.testing import KopfRunner

# Global list to track reimport-scan requests
reimport_scan_requests = []


class _DefectDojoMockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/v2/reimport-scan/":
            # read and capture body
            length = int(self.headers.get("Content-Length", 0))
            body_bytes = b""
            if length:
                body_bytes = self.rfile.read(length)

            # Store the request body for verification
            reimport_scan_requests.append(body_bytes)

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
    # clean up any previous debug output so comparisons start fresh
    debug_dir = os.path.join("tests", "debug")
    if os.path.isdir(debug_dir):
        shutil.rmtree(debug_dir)

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

        # Parse the request bodies as JSON
        bodies = []
        for req_body in reimport_scan_requests:
            try:
                bodies.append(json.loads(req_body.decode('utf-8')))
            except json.JSONDecodeError:
                bodies.append(req_body.decode('utf-8'))

        # Extract active values from requests
        active_values = [body.get("active")
                         for body in bodies if isinstance(body, dict)]

        # Verify we have one "active = true" and one "active = false"
        assert len(
            active_values) == 2, f"Expected 2 requests with 'active' field, got {len(active_values)}"
        assert True in active_values, "Expected at least one request with 'active = true'"
        assert False in active_values, "Expected at least one request with 'active = false'"

    finally:
        # Clear the global list for next test run
        reimport_scan_requests.clear()
        server.shutdown()
        server.server_close()
