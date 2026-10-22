"""Tests for the AI security review gate. Run: python -m pytest ai-security-review/gate"""

import copy
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gate  # noqa: E402

POLICY = gate.load_policy(gate.DEFAULT_POLICY)

# Trimmed pull_request "opened" event payload, with only the fields the gate reads.
BASE_EVENT = {
    "action": "opened",
    "pull_request": {
        "number": 42,
        "additions": 40,
        "deletions": 5,
        "changed_files": 3,
        "user": {"login": "a-developer", "type": "User"},
        "head": {"repo": {"full_name": "mozilla/example-service"}},
        "base": {"repo": {"full_name": "mozilla/example-service"}},
    },
}


def event(**pr_overrides):
    e = copy.deepcopy(BASE_EVENT)
    e["pull_request"].update(pr_overrides)
    return e


def f(filename, additions=1, deletions=0, status="modified", **extra):
    return {"filename": filename, "additions": additions, "deletions": deletions,
            "status": status, **extra}


def run(e, files, event_name="pull_request"):
    return (gate.check_payload(event_name, e, POLICY)
            or gate.check_files(e["pull_request"], files, POLICY))


# --- glob matching -----------------------------------------------------------

@pytest.mark.parametrize("pattern,path,expected", [
    ("docs/**", "docs/a/b.md", True),
    ("docs/**", "src/docs/a.md", False),
    ("*.md", "README.md", True),
    ("*.md", "deep/dir/NOTES.md", True),
    ("**/tests/**", "tests/test_x.py", True),
    ("**/tests/**", "pkg/tests/unit/test_x.py", True),
    ("**/tests/**", "pkg/testsuite.py", False),
    ("src/auth/**", "src/auth/login.py", True),
    ("src/auth/**", "src/authz/login.py", False),
    ("src/*.py", "src/a/b.py", False),
    ("requirements*.txt", "services/api/requirements-dev.txt", True),
    ("package.json", "package-lock.json", False),
])
def test_path_matches(pattern, path, expected):
    assert gate.path_matches(path, [pattern]) is expected


# --- hard skips --------------------------------------------------------------

def test_skips_non_pull_request_events():
    scan, reason = run(event(), [f("app.py", 500)], event_name="merge_group")
    assert not scan and "merge_group" in reason


def test_skips_fork_prs():
    e = event()
    e["pull_request"]["head"]["repo"]["full_name"] = "someone/example-service"
    scan, reason = run(e, [f("app.py", 500)])
    assert not scan and "fork" in reason


def test_skips_when_head_repo_was_deleted():
    e = event()
    e["pull_request"]["head"]["repo"] = None
    assert run(e, [f("app.py")])[0] is False


def test_skips_bots():
    e = event(user={"login": "dependabot[bot]", "type": "Bot"})
    scan, reason = run(e, [f("package.json", 3)])
    assert not scan and "dependabot[bot]" in reason


def test_drafts_are_scanned():
    scan, reason = run(event(draft=True, additions=500), [f("app.py", 500)])
    assert scan and reason.startswith("rule large-change")


# --- docs / tests only ---------------------------------------------------------

def test_skips_docs_and_tests_only():
    files = [f("docs/guide.md", 400), f("README.md"), f("tests/test_api.py", 200)]
    scan, reason = run(event(additions=601), files)
    assert not scan and "documentation or test" in reason


def test_skips_empty_file_list():
    assert run(event(), [])[0] is False


def test_rename_from_code_into_tests_is_not_tests_only():
    files = [f("tests/session.py", status="renamed", previous_filename="src/auth/session.py")]
    scan, reason = run(event(additions=400), files)
    assert scan and reason.startswith("rule large-change")


# --- triggers --------------------------------------------------------------------

def test_dependency_manifest_under_docs_still_triggers():
    scan, reason = run(event(), [f("docs/requirements.txt", 1)])
    assert scan and reason.startswith("rule new-dependencies")


def test_new_dependency_trigger():
    scan, reason = run(event(), [f("services/api/requirements.txt", 2)])
    assert scan and reason.startswith("rule new-dependencies")


def test_removed_manifest_or_deletions_only_do_not_trigger():
    files = [f("package.json", 0, 3), f("old/go.mod", 0, 10, status="removed")]
    assert run(event(), files)[0] is False


def test_lockfile_alone_does_not_trigger():
    assert run(event(), [f("package-lock.json", 120)])[0] is False


def test_large_change_trigger():
    scan, reason = run(event(additions=250, deletions=60), [f("app.py", 250, 60)])
    assert scan and "310 lines changed (threshold 300)" in reason


def test_below_threshold_skips():
    scan, reason = run(event(additions=100, deletions=20), [f("app.py", 100, 20)])
    assert not scan and "no rule matched" in reason


def test_evidence_is_truncated():
    files = [f(f"svc{i}/requirements.txt") for i in range(5)]
    reason = run(event(), files)[1]
    assert reason.endswith("(+2 more)")


# --- main(): outputs and fail-safe behaviour ----------------------------------

@pytest.fixture
def actions_env(tmp_path, monkeypatch):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event(additions=500, deletions=0)))
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.delenv("POLICY_PATH", raising=False)
    return output, summary


def test_main_writes_outputs_and_summary(actions_env, monkeypatch):
    output, summary = actions_env
    monkeypatch.setattr(gate, "has_security_comment", lambda *a: False)
    monkeypatch.setattr(gate, "fetch_pr_files", lambda *a: [f("app.py", 500)])
    assert gate.main() == 0
    assert output.read_text().splitlines() == [
        "scan=true",
        "reason=rule large-change: 500 lines changed (threshold 300)",
    ]
    assert "AI security review will run" in summary.read_text()


def test_main_skips_api_calls_for_payload_decisions(actions_env, monkeypatch):
    e = event(user={"login": "dependabot[bot]", "type": "Bot"})
    Path(gate.os.environ["GITHUB_EVENT_PATH"]).write_text(json.dumps(e))

    def must_not_call(*a):
        raise AssertionError("API called for a payload-only decision")

    monkeypatch.setattr(gate, "fetch_pr_files", must_not_call)
    monkeypatch.setattr(gate, "has_security_comment", must_not_call)
    gate.main()
    assert "skip: author dependabot[bot] is a bot" in actions_env[0].read_text()


def test_main_fails_safe_on_api_error(actions_env, monkeypatch, capsys):
    def boom(*a):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(gate, "has_security_comment", lambda *a: False)
    monkeypatch.setattr(gate, "fetch_pr_files", boom)
    assert gate.main() == 0
    out = actions_env[0].read_text()
    assert "scan=false" in out and "gate error" in out
    assert "::warning title=AI security review skipped::" in capsys.readouterr().out


def test_warning_message_is_escaped(actions_env, monkeypatch, capsys):
    def boom(*a):
        raise urllib.error.URLError("bad url https://x/%0A::error::injected\nline")

    monkeypatch.setattr(gate, "has_security_comment", lambda *a: False)
    monkeypatch.setattr(gate, "fetch_pr_files", boom)
    gate.main()
    warning = [l for l in capsys.readouterr().out.splitlines() if l.startswith("::warning")]
    assert len(warning) == 1
    assert "%250A::error::injected%0Aline" in warning[0]


def test_main_does_not_warn_on_normal_skip(actions_env, monkeypatch, capsys):
    monkeypatch.setattr(gate, "has_security_comment", lambda *a: False)
    monkeypatch.setattr(gate, "fetch_pr_files", lambda *a: [f("README.md")])
    gate.main()
    assert "::warning" not in capsys.readouterr().out


def test_outputs_are_single_line(actions_env):
    gate.write_outputs(True, "rule new-dependencies: lines added to evil\nscan=false")
    lines = actions_env[0].read_text().splitlines()
    assert lines == ["scan=true", "reason=rule new-dependencies: lines added to evil scan=false"]


def test_summary_renders_untrusted_names_literally(actions_env):
    gate.write_outputs(True, "rule new-dependencies: lines added to [x](https://evil)`<img src=x>`.py")
    summary = actions_env[1].read_text()
    assert "`rule new-dependencies: lines added to [x](https://evil)'<img src=x>'.py`" in summary


def test_fetch_pr_files_paginates(monkeypatch):
    pages = {1: [f(f"a{i}.py") for i in range(100)], 2: [f("last.py")]}

    def fake_request(url, token):
        page = int(url.rsplit("page=", 1)[1])
        return json.dumps(pages[page]).encode()

    monkeypatch.setattr(gate, "_request", fake_request)
    files = gate.fetch_pr_files("https://api.github.com", "o/r", 1, "t")
    assert len(files) == 101


# --- too big / already reviewed ------------------------------------------------

def _write_event(e):
    Path(gate.os.environ["GITHUB_EVENT_PATH"]).write_text(json.dumps(e))


class FakeGitHub:
    """Stands in for gate._request: serves GET pages and records POSTs."""

    def __init__(self, pages):
        self.pages = pages  # path -> list of items
        self.posts = []

    def __call__(self, url, token, data=None):
        path = url.split("api.github.com", 1)[1].split("?", 1)[0]
        if data is not None:
            self.posts.append((path, data))
            return b"{}"
        return json.dumps(self.pages.get(path, [])).encode()


def test_too_big_skips_and_comments_once(actions_env, monkeypatch):
    _write_event(event(changed_files=101))
    github = FakeGitHub({})
    monkeypatch.setattr(gate, "_request", github)
    gate.main()
    assert "skip: too big (101 files changed, limit 100)" in actions_env[0].read_text()
    [(path, data)] = github.posts
    assert path == "/repos/mozilla/example-service/issues/42/comments"
    assert data["body"].startswith(gate.TOO_BIG_MARKER)
    assert "101 files" in data["body"]


def test_too_big_comment_is_not_repeated(actions_env, monkeypatch):
    _write_event(event(changed_files=150))
    existing = [{"body": gate.TOO_BIG_MARKER + "\nAI security review skipped"}]
    github = FakeGitHub({"/repos/mozilla/example-service/issues/42/comments": existing})
    monkeypatch.setattr(gate, "_request", github)
    gate.main()
    assert github.posts == []
    assert "skip: too big" in actions_env[0].read_text()


def test_exactly_max_files_is_not_too_big():
    assert gate.too_big(event(changed_files=100)["pull_request"], POLICY) is False


def test_skips_when_already_reviewed(actions_env, monkeypatch):
    comments = [{"user": {"type": "Bot"}, "body": "\U0001F916 **Security Issue: SQL injection**"}]
    github = FakeGitHub({"/repos/mozilla/example-service/pulls/42/comments": comments})
    monkeypatch.setattr(gate, "_request", github)
    gate.main()
    assert "skip: an earlier review already posted security comments" in actions_env[0].read_text()


def test_human_comment_with_marker_does_not_count(monkeypatch):
    comments = [{"user": {"type": "User"}, "body": "\U0001F916 **Security Issue: fake"}]
    monkeypatch.setattr(gate, "_request", FakeGitHub({"/repos/o/r/pulls/1/comments": comments}))
    assert gate.has_security_comment("https://api.github.com", "o/r", 1, "t") is False
