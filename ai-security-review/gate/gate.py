#!/usr/bin/env python3
"""Decide whether a pull request should get an AI security review.

Reads the pull_request event payload and the PR's changed files (GitHub API),
then applies the central policy in ../policy/default.yml. The caller runs the
gate when a PR is opened, reopened or marked ready, and again when the
`rescan_label` is added; the gate removes that label so it can be re-applied
and, if a new review will run, deletes the earlier inline findings.
A PR with too many files is not scanned; the gate posts a one-time comment
asking for a separate review instead.

Writes `scan` (true/false) and `reason` to $GITHUB_OUTPUT and a short
explanation to $GITHUB_STEP_SUMMARY. Any error results in scan=false so the
gate never blocks a pull request, plus a warning annotation so the missed scan
is visible on the PR's checks.
"""

import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

import yaml

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy" / "default.yml"
MAX_PAGES = 30  # of 100 items; GitHub caps the PR files API at 3000 files
MAX_EVIDENCE = 3 # How many file names the gate puts in its reason string

# Marker of the inline comments posted by mozilla/claude-code-security-review
# (scripts/comment-pr-findings.js, which skips posting when it finds this
# marker). Keep in sync: if the fork's wording changes, nothing gets deleted.
SECURITY_COMMENT_MARKER = "\U0001F916 **Security Issue:"
# Hidden marker identifying the gate's own "too big" PR comment.
TOO_BIG_MARKER = "<!-- ai-security-review:too-big -->"


# --- glob matching -----------------------------------------------------------

def path_matches(path, patterns):
    """`*` matches within a path segment, `**` across segments. Patterns
    without a `/` match the file name in any directory."""
    p = PurePosixPath(path)
    return any(p.full_match(pat if "/" in pat else f"**/{pat}") for pat in patterns)


def _names(f):
    """Current and, for renames, previous path of a changed file."""
    names = [f["filename"]]
    if f.get("previous_filename"):
        names.append(f["previous_filename"])
    return names


# --- policy ------------------------------------------------------------------

def load_policy(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# --- decision ----------------------------------------------------------------

def _evidence(paths):
    shown = ", ".join(paths[:MAX_EVIDENCE])
    if len(paths) > MAX_EVIDENCE:
        shown += f" (+{len(paths) - MAX_EVIDENCE} more)"
    return shown


def is_rescan_label(event, policy):
    """True for a `labeled` event that added the policy's rescan label."""
    label = policy.get("rescan_label")
    return bool(label) and event.get("action") == "labeled" \
        and (event.get("label") or {}).get("name") == label


def check_payload(event_name, event, policy):
    """Decisions that need only the event payload. Returns (scan, reason) or None."""
    if event_name != "pull_request":
        return False, f"skip: event '{event_name}' is not pull_request"

    pr = event["pull_request"]
    skip = policy.get("skip", {})

    # Any other label added to the PR also starts the workflow; ignore it.
    if event.get("action") == "labeled" and not is_rescan_label(event, policy):
        label = (event.get("label") or {}).get("name")
        return False, f"skip: label {label} is not the rescan label"

    head_repo = (pr.get("head") or {}).get("repo") or {}
    base_repo = (pr.get("base") or {}).get("repo") or {}
    if not head_repo or head_repo.get("full_name") != base_repo.get("full_name"):
        return False, "skip: pull request comes from a fork"

    opt_out = skip.get("opt_out_label")
    if opt_out and any(l.get("name") == opt_out for l in pr.get("labels") or []):
        return False, f"skip: pull request has the {opt_out} label"

    user = pr.get("user") or {}
    if skip.get("bot_authors", True) and user.get("type") == "Bot":
        return False, f"skip: author {user.get('login')} is a bot"
    return None


def too_big(pr, policy):
    """The review and its PR comments only cover the first 100 changed files."""
    return pr.get("changed_files", 0) > int(policy["max_changed_files"])


def check_files(pr, files, policy):
    """Decisions based on the changed files. Returns (scan, reason)."""
    if not files:
        return False, "skip: no changed files"

    # The dependency trigger comes first so the docs/tests skip can never hide
    # it (e.g. docs/requirements.txt).
    manifests = policy.get("dependency_manifests", [])
    dep_hits = [
        f["filename"]
        for f in files
        if f.get("status") != "removed"
        and f.get("additions", 0) > 0
        and path_matches(f["filename"], manifests)
    ]
    if dep_hits:
        return True, f"rule new-dependencies: lines added to {_evidence(dep_hits)}"

    skip = policy.get("skip", {})
    ignorable = skip.get("docs_globs", []) + skip.get("test_globs", [])
    # A file moved from code into docs/ or tests/ still counts as code.
    code = [f["filename"] for f in files
            if not all(path_matches(n, ignorable) for n in _names(f))]
    if not code:
        return False, "skip: only documentation or test files changed"

    return True, f"rule code-change: {_evidence(code)}"


# --- GitHub API --------------------------------------------------------------

def _request(url, token, data=None, method=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "mozilla-ssdlc-ai-security-review-gate",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _paginate(url, token):
    items = []
    for page in range(1, MAX_PAGES + 1):
        batch = json.loads(_request(f"{url}?per_page=100&page={page}", token))
        items.extend(batch)
        if len(batch) < 100:
            break
    return items


def fetch_pr_files(api, repo, number, token):
    return _paginate(f"{api}/repos/{repo}/pulls/{number}/files", token)


def remove_label(api, repo, number, label, token):
    """Remove the rescan label so it can be applied again. Best effort."""
    url = f"{api}/repos/{repo}/issues/{number}/labels/{urllib.parse.quote(label, safe='')}"
    try:
        _request(url, token, method="DELETE")
    except Exception as e:  # the label may already be gone; never block the scan
        print(f"::warning title=Could not remove rescan label::{_command_data(e)}")


def delete_old_findings(api, repo, number, token):
    """Delete earlier inline security findings so a rescan can post new ones.

    The review action skips posting when the PR already has any of its comments
    (resolved or not), so a requested rescan would otherwise post nothing.
    Best effort: failures only emit warnings. Returns a short description for
    the decision reason.
    """
    try:
        comments = _paginate(f"{api}/repos/{repo}/pulls/{number}/comments", token)
    except Exception as e:
        print(f"::warning title=Could not list old findings::{_command_data(e)}")
        return "could not list earlier findings"
    old = [c for c in comments
           if (c.get("user") or {}).get("type") == "Bot"
           and SECURITY_COMMENT_MARKER in (c.get("body") or "")]
    failed = 0
    for c in old:
        try:
            _request(f"{api}/repos/{repo}/pulls/comments/{c['id']}", token, method="DELETE")
        except Exception as e:
            failed += 1
            print(f"::warning title=Could not delete an old finding::{_command_data(e)}")
    if not old:
        return "no earlier findings to delete"
    if failed:
        return f"deleted {len(old) - failed} of {len(old)} earlier findings, {failed} failed"
    return f"deleted {len(old)} earlier findings"


def comment_too_big(api, repo, pr, max_files, token):
    """Post the "too big" PR comment unless it is already there."""
    url = f"{api}/repos/{repo}/issues/{pr['number']}/comments"
    if any(TOO_BIG_MARKER in (c.get("body") or "") for c in _paginate(url, token)):
        return
    body = (
        f"{TOO_BIG_MARKER}\n"
        f"**AI security review skipped:** this pull request changes {pr['changed_files']} files, "
        f"more than the {max_files} the automated review supports.\n\n"
        "Split it into smaller pull requests, or ask the security team to review it separately."
    )
    _request(url, token, data={"body": body})


# --- outputs -----------------------------------------------------------------

def _one_line(text):
    return " ".join(str(text).split())


def _command_data(text):
    """Escape a workflow command message, as @actions/core's escapeData does."""
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _code_span(text):
    """Render untrusted text (file names, bot logins) literally in Markdown."""
    return "`" + _one_line(text).replace("`", "'") + "`"


def write_outputs(scan, reason):
    reason = _one_line(reason)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write(f"scan={'true' if scan else 'false'}\n")
            f.write(f"reason={reason}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        verdict = "will run" if scan else "skipped"
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### AI security review {verdict}\n\n{_code_span(reason)}\n")
    print(f"scan={'true' if scan else 'false'} reason={reason}")


def main():
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    try:
        policy = load_policy(os.environ.get("POLICY_PATH") or DEFAULT_POLICY)
        with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
            event = json.load(f)

        decision = check_payload(event_name, event, policy)
        if decision is None:
            api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
            token = os.environ["GITHUB_TOKEN"]
            pr = event["pull_request"]
            repo = pr["base"]["repo"]["full_name"]
            max_files = int(policy["max_changed_files"])
            if is_rescan_label(event, policy):
                remove_label(api, repo, pr["number"], policy["rescan_label"], token)
            if too_big(pr, policy):
                comment_too_big(api, repo, pr, max_files, token)
                decision = False, f"skip: too big ({pr['changed_files']} files changed, limit {max_files})"
            else:
                files = fetch_pr_files(api, repo, pr["number"], token)
                scan, reason = check_files(pr, files, policy)
                # Only clear old findings when a new review will replace them.
                if scan and is_rescan_label(event, policy):
                    reason += f" ({delete_old_findings(api, repo, pr['number'], token)})"
                decision = scan, reason
        scan, reason = decision
    except Exception as e:  # never block the PR
        scan, reason = False, f"skip: gate error ({type(e).__name__}: {e})"
        print(f"::warning title=AI security review skipped::{_command_data(reason)}")
    write_outputs(scan, reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
