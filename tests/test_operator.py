import os
import subprocess
import time

from kopf.testing import KopfRunner

os.environ.setdefault("DEFECT_DOJO_API_KEY", "test-api-key")
os.environ.setdefault("DEFECT_DOJO_URL", "http://localhost:8080")


def test_operator():
    with KopfRunner(['run', '-A', '--verbose', 'src/handlers.py']) as runner:
        # do something while the operator is running.

        subprocess.run("kubectl apply -f tests/resources/trivy_report_manifest.yaml",
                       shell=True, check=True)
        time.sleep(1)  # give it some time to react and to sleep and to retry

        subprocess.run("kubectl delete -f tests/resources/trivy_report_manifest.yaml",
                       shell=True, check=True)
        time.sleep(1)  # give it some time to react

    assert runner.exit_code == 0
    assert runner.exception is None
    assert 'And here we are!' in runner.output
    assert 'Deleted, really deleted' in runner.output
