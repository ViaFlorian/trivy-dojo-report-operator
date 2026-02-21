import os
import subprocess
import time

from kopf.testing import KopfRunner

os.environ.setdefault("DEFECT_DOJO_API_KEY", "test-api-key")
os.environ.setdefault("DEFECT_DOJO_URL", "http://localhost:8080")


def test_operator():
    with KopfRunner(['run', '-A', '--verbose', 'src/handlers.py']) as runner:
        # do something while the operator is running.

        subprocess.run("kubectl apply -f tests/resources/simple_old_container_deployment.yaml",
                       shell=True, check=True)
        
        # Wait until vulnerability report is created
        timeout = 30
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = subprocess.run("kubectl get vulnerabilityreports --all-namespaces", 
                                   shell=True, capture_output=True, text=True)
            if result.stdout and "simple-alpine-deployment" in result.stdout:
                break
            time.sleep(1)

        subprocess.run("kubectl delete -f tests/resources/simple_old_container_deployment.yaml",
                       shell=True, check=True)
        time.sleep(1)  # give it some time to react

    assert runner.exit_code == 0
    assert runner.exception is None
    assert 'And here we are!' in runner.output
    assert 'Deleted, really deleted' in runner.output
