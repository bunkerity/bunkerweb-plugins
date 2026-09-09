"""Execute the release signature gate with controlled GitHub responses."""

import json
import os
from pathlib import Path
import subprocess
from textwrap import dedent

import pytest


@pytest.mark.parametrize("case", ["valid", "lightweight", "unsigned", "wrong_target", "failed_tests", "api_error"])
def test_signed_release_gate(case):
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
    step = workflow.split("      - name: Verify signed tag and successful tests\n", 1)[1].split("      - name:", 1)[0]
    script = dedent(step.split("        run: |\n", 1)[1])
    tag_ref = {"object": {"type": "commit" if case == "lightweight" else "tag", "sha": "tag-object"}}
    tag = {"verification": {"verified": case != "unsigned"}, "object": {"type": "commit", "sha": "wrong" if case == "wrong_target" else "tested"}}
    runs = [
        {"workflow_runs": [{"head_sha": "tested", "head_branch": "main", "event": "push", "conclusion": "failure" if case == "failed_tests" else "success"}]}
    ]
    mock = """
gh() {
    if [ "$CASE" = api_error ]; then return 1; fi
    case "$*" in
      *git/ref/tags/*) printf '%s' "$TAG_REF" ;;
      *git/tags/*) printf '%s' "$TAG_OBJECT" ;;
      *actions/workflows/*) printf '%s' "$RUNS" ;;
      *) return 1 ;;
    esac
}
"""
    result = subprocess.run(
        ["bash", "-e", "-c", mock + script],
        env={
            **os.environ,
            "CASE": case,
            "TAG_REF": json.dumps(tag_ref),
            "TAG_OBJECT": json.dumps(tag),
            "RUNS": json.dumps(runs),
            "GITHUB_REPOSITORY": "test/plugins",
            "GITHUB_SHA": "tested",
            "TAG": "v1.12",
        },
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) == (case == "valid"), result.stdout + result.stderr
