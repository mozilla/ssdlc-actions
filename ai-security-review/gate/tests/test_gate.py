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


def test_skips_opt_out_label():
    e = event(labels=[{"name": "bug"}, {"name": "skip-ai-review"}])
    scan, reason = run(e, [f("app.py", 500)])
    assert not scan and "skip-ai-review" in reason


def test_other_labels_do_not_opt_out():
    assert run(event(labels=[{"name": "bug"}]), [f("app.py")])[0] is True


def test_opt_out_label_wins_over_rescan_label(actions_env, monkeypatch):
    e = labeled_event("ai-review", labels=[{"name": "ai-review"}, {"name": "skip-ai-review"}])
    _write_event(e)

    def must_not_call(*a, **kw):
        raise AssertionError("API called for an opted-out PR")

    monkeypatch.setattr(gate, "_request", must_not_call)
    gate.main()
    assert "skip-ai-review label" in actions_env[0].read_text()


def test_drafts_are_scanned():
    scan, reason = run(event(draft=True), [f("app.py")])
    assert scan and reason.startswith("rule code-change")


# --- docs / tests only ---------------------------------------------------------

def test_skips_docs_and_tests_only():
    files = [f("docs/guide.md", 400), f("README.md"), f("tests/test_api.py", 200)]
    scan, reason = run(event(), files)
    assert not scan and "documentation or test" in reason


def test_skips_empty_file_list():
    assert run(event(), [])[0] is False


def test_rename_from_code_into_tests_is_not_tests_only():
    files = [f("tests/session.py", status="renamed", previous_filename="src/auth/session.py")]
    scan, reason = run(event(), files)
    assert scan and reason.startswith("rule code-change")


# --- triggers --------------------------------------------------------------------

def test_dependency_manifest_under_docs_still_triggers():
    scan, reason = run(event(), [f("docs/requirements.txt", 1)])
    assert scan and reason.startswith("rule new-dependencies")


def test_new_dependency_trigger():
    scan, reason = run(event(), [f("services/api/requirements.txt", 2)])
    assert scan and reason.startswith("rule new-dependencies")


def test_removed_manifest_or_deletions_only_are_not_new_dependencies():
    files = [f("package.json", 0, 3), f("old/go.mod", 0, 10, status="removed")]
    assert run(event(), files)[1].startswith("rule code-change")


def test_lockfile_alone_is_not_a_new_dependency():
    assert run(event(), [f("package-lock.json", 120)])[1] == "rule code-change: package-lock.json"


def test_any_code_change_is_reviewed():
    files = [f("README.md", 50), f("src/app.py", 1)]
    scan, reason = run(event(), files)
    assert scan and reason == "rule code-change: src/app.py"


def test_evidence_is_truncated():
    files = [f(f"svc{i}/requirements.txt") for i in range(5)]
    reason = run(event(), files)[1]
    assert reason.endswith("(+2 more)")


# --- main(): outputs and fail-safe behaviour ----------------------------------

@pytest.fixture
def actions_env(tmp_path, monkeypatch):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event()))
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
    monkeypatch.setattr(gate, "fetch_pr_files", lambda *a: [f("app.py", 500)])
    assert gate.main() == 0
    assert output.read_text().splitlines() == [
        "scan=true",
        "reason=rule code-change: app.py",
    ]
    assert "AI security review will run" in summary.read_text()


def test_main_skips_api_calls_for_payload_decisions(actions_env, monkeypatch):
    e = event(user={"login": "dependabot[bot]", "type": "Bot"})
    Path(gate.os.environ["GITHUB_EVENT_PATH"]).write_text(json.dumps(e))

    def must_not_call(*a):
        raise AssertionError("API called for a payload-only decision")

    monkeypatch.setattr(gate, "fetch_pr_files", must_not_call)
    gate.main()
    assert "skip: author dependabot[bot] is a bot" in actions_env[0].read_text()


def test_main_fails_safe_on_api_error(actions_env, monkeypatch, capsys):
    def boom(*a):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(gate, "fetch_pr_files", boom)
    assert gate.main() == 0
    out = actions_env[0].read_text()
    assert "scan=false" in out and "gate error" in out
    assert "::warning title=AI security review skipped::" in capsys.readouterr().out


def test_warning_message_is_escaped(actions_env, monkeypatch, capsys):
    def boom(*a):
        raise urllib.error.URLError("bad url https://x/%0A::error::injected\nline")

    monkeypatch.setattr(gate, "fetch_pr_files", boom)
    gate.main()
    warning = [l for l in capsys.readouterr().out.splitlines() if l.startswith("::warning")]
    assert len(warning) == 1
    assert "%250A::error::injected%0Aline" in warning[0]


def test_main_does_not_warn_on_normal_skip(actions_env, monkeypatch, capsys):
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


# --- too big ------------------------------------------------

def _write_event(e):
    Path(gate.os.environ["GITHUB_EVENT_PATH"]).write_text(json.dumps(e))


class FakeGitHub:
    """Stands in for gate._request: serves GET pages and records POSTs."""

    def __init__(self, pages):
        self.pages = pages  # path -> list of items
        self.posts = []

    def __call__(self, url, token, data=None, method=None):
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


# --- rescan label ----------------------------------------------------------------

def labeled_event(label, **pr_overrides):
    e = event(**pr_overrides)
    e["action"] = "labeled"
    e["label"] = {"name": label}
    return e


def test_unrelated_label_is_skipped_without_api_calls(actions_env, monkeypatch):
    _write_event(labeled_event("bug"))

    def must_not_call(*a, **kw):
        raise AssertionError("API called for an unrelated label")

    monkeypatch.setattr(gate, "_request", must_not_call)
    gate.main()
    assert "skip: label bug is not the rescan label" in actions_env[0].read_text()


def test_rescan_label_runs_gate_and_is_removed(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))
    calls = []

    def fake(url, token, data=None, method=None):
        path = url.split("api.github.com", 1)[1].split("?", 1)[0]
        calls.append((method, path))
        return json.dumps([f("app.py")] if path.endswith("/files") else []).encode()

    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "scan=true" in actions_env[0].read_text()
    assert ("DELETE", "/repos/mozilla/example-service/issues/42/labels/ai-review") in calls


def test_rescan_label_does_not_override_file_rules(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))

    def fake(url, token, data=None, method=None):
        return json.dumps([f("README.md")] if url.split("?")[0].endswith("/files") else []).encode()

    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "scan=false" in actions_env[0].read_text()
    assert "documentation or test" in actions_env[0].read_text()


def test_label_removal_failure_does_not_block_scan(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))

    def fake(url, token, data=None, method=None):
        if method == "DELETE":
            raise urllib.error.URLError("404")
        return json.dumps([f("app.py")] if url.split("?")[0].endswith("/files") else []).encode()

    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "scan=true" in actions_env[0].read_text()


def test_is_rescan_label_ignores_other_actions():
    e = event()
    e["label"] = {"name": "ai-review"}
    assert gate.is_rescan_label(e, POLICY) is False


# --- deleting old findings on rescan -------------------------------------------------

FINDING = {"id": 7, "user": {"type": "Bot"}, "body": "\U0001F916 **Security Issue: SQL injection**"}


def _rescan_github(files, comments, delete_error=None):
    calls = []

    def fake(url, token, data=None, method=None):
        path = url.split("api.github.com", 1)[1].split("?", 1)[0]
        calls.append((method, path))
        if method == "DELETE" and "/pulls/comments/" in path and delete_error:
            raise delete_error
        if path.endswith("/files"):
            return json.dumps(files).encode()
        if path.endswith("/pulls/42/comments"):
            return json.dumps(comments).encode()
        return b"[]"

    return fake, calls


def test_rescan_deletes_only_bot_security_findings(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))
    other = [
        {"id": 8, "user": {"type": "User"}, "body": "\U0001F916 **Security Issue: fake"},
        {"id": 9, "user": {"type": "Bot"}, "body": "some other bot comment"},
    ]
    fake, calls = _rescan_github([f("app.py")], [FINDING] + other)
    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    deletes = [p for m, p in calls if m == "DELETE" and "/pulls/comments/" in p]
    assert deletes == ["/repos/mozilla/example-service/pulls/comments/7"]
    assert "(deleted 1 earlier findings)" in actions_env[0].read_text()


def test_no_deletion_when_rescan_is_skipped(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))
    fake, calls = _rescan_github([f("README.md")], [FINDING])
    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "scan=false" in actions_env[0].read_text()
    assert not [1 for m, p in calls if m == "DELETE" and "/pulls/comments/" in p]


def test_no_deletion_on_opened_event(actions_env, monkeypatch):
    fake, calls = _rescan_github([f("app.py")], [FINDING])
    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "scan=true" in actions_env[0].read_text()
    assert not [1 for m, p in calls if m == "DELETE"]


def test_delete_failure_does_not_block_scan(actions_env, monkeypatch, capsys):
    _write_event(labeled_event("ai-review"))
    fake, _ = _rescan_github([f("app.py")], [FINDING], delete_error=urllib.error.URLError("403"))
    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "scan=true" in actions_env[0].read_text()
    assert "::warning title=Could not delete an old finding" in capsys.readouterr().out


def test_delete_failure_is_reported_in_reason(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))
    fake, _ = _rescan_github([f("app.py")], [FINDING], delete_error=urllib.error.URLError("403"))
    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "deleted 0 of 1 earlier findings, 1 failed" in actions_env[0].read_text()


def test_list_failure_does_not_block_scan_and_is_reported(actions_env, monkeypatch, capsys):
    _write_event(labeled_event("ai-review"))

    def fake(url, token, data=None, method=None):
        path = url.split("api.github.com", 1)[1].split("?", 1)[0]
        if path.endswith("/pulls/42/comments"):
            raise urllib.error.URLError("500")
        return json.dumps([f("app.py")] if path.endswith("/files") else []).encode()

    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    out = actions_env[0].read_text()
    assert "scan=true" in out and "could not list earlier findings" in out
    assert "::warning title=Could not list old findings" in capsys.readouterr().out


def test_rescan_with_no_earlier_findings(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))
    fake, calls = _rescan_github([f("app.py")], [])
    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert "no earlier findings to delete" in actions_env[0].read_text()


def test_old_findings_are_found_across_pages(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))
    filler = [{"id": i, "user": {"type": "User"}, "body": "x"} for i in range(100)]
    pages = {1: filler, 2: [FINDING]}
    deleted = []

    def fake(url, token, data=None, method=None):
        path = url.split("api.github.com", 1)[1].split("?", 1)[0]
        if method == "DELETE" and "/pulls/comments/" in path:
            deleted.append(path)
            return b"{}"
        if path.endswith("/files"):
            return json.dumps([f("app.py")]).encode()
        if path.endswith("/pulls/42/comments"):
            return json.dumps(pages[int(url.rsplit("page=", 1)[1])]).encode()
        return b"[]"

    monkeypatch.setattr(gate, "_request", fake)
    gate.main()
    assert deleted == ["/repos/mozilla/example-service/pulls/comments/7"]


def test_label_removal_failure_still_deletes_old_findings(actions_env, monkeypatch):
    _write_event(labeled_event("ai-review"))
    fake, calls = _rescan_github([f("app.py")], [FINDING])

    def wrapper(url, token, data=None, method=None):
        if method == "DELETE" and "/labels/" in url:
            raise urllib.error.URLError("404")
        return fake(url, token, data, method)

    monkeypatch.setattr(gate, "_request", wrapper)
    gate.main()
    assert "(deleted 1 earlier findings)" in actions_env[0].read_text()
