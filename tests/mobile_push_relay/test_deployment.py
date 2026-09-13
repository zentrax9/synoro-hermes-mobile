from pathlib import Path
import re


ROOT = Path(__file__).parents[2]
SERVICE = ROOT / "services" / "mobile_push_relay"


def test_docker_base_and_cloud_run_template_require_immutable_images():
    dockerfile = (SERVICE / "Dockerfile").read_text(encoding="utf-8")
    manifest = (SERVICE / "cloud-run.service.yaml").read_text(encoding="utf-8")
    deploy = (SERVICE / "deploy.sh").read_text(encoding="utf-8")

    assert re.search(r"^ARG PYTHON_IMAGE=.+@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE)
    assert "image: __RELAY_IMAGE_DIGEST__" in manifest
    assert "@sha256:" in deploy
    assert "readOnlyRootFilesystem: true" in manifest
    assert "runAsNonRoot: true" in manifest
    assert "mountPath: /tmp" in manifest
    assert "medium: Memory" in manifest
    assert "--proxy-headers" not in dockerfile


def test_cloud_run_template_is_production_firestore_and_not_public_by_default():
    manifest = (SERVICE / "cloud-run.service.yaml").read_text(encoding="utf-8")

    assert "value: firestore" in manifest
    assert "value: production" in manifest
    assert "run.googleapis.com/ingress: internal-and-cloud-load-balancing" in manifest
    assert "__RELAY_SERVICE_ACCOUNT__" in manifest
    assert "__RELAY_PROJECT_ID__" in manifest
    assert "password" not in manifest.lower()
    assert "secret" not in manifest.lower()


def test_cloud_run_check_script_checks_durability_controls():
    checker = (SERVICE / "check_cloud_run.sh").read_text(encoding="utf-8")

    for required in (
        "@sha256:[0-9a-f]{64}",
        "serviceAccountName",
        "runAsNonRoot: true",
        "readOnlyRootFilesystem: true",
        "mountPath: /tmp",
        "medium: Memory",
        "RELAY_BACKEND",
        "value: firestore",
        "run.googleapis.com/ingress",
        "internal-and-cloud-load-balancing",
    ):
        assert required in checker
