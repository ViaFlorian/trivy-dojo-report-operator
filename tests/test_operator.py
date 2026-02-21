import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from kopf.testing import KopfRunner


class _DefectDojoMockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/v2/reimport-scan/":
            # read and discard body (could be multipart/form-data)
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(length)
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
    # start a mock DefectDojo HTTP server on a random free port
    server = ThreadingHTTPServer(("localhost", 0), _DefectDojoMockHandler)
    port = server.server_address[1]
    os.environ.setdefault("DEFECT_DOJO_API_KEY", "test-api-key")
    os.environ.setdefault("DEFECT_DOJO_URL", f"http://localhost:{port}")

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

    finally:
        server.shutdown()
        server.server_close()
