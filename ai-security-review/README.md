# AI Security Review (POC)

Runs an AI security review on pull requests, but only when the rules say a scan is worth it. Findings are posted as inline PR review comments. The workflow never fails because of findings.

```
caller workflow (in your repo)
  └─ .github/workflows/ai-security-review.yml   (reusable, in this repo)
       ├─ gate:   ai-security-review/gate        decides scan / skip, writes the reason to the job summary
       └─ review: mozilla/claude-code-security-review (fork of anthropics/claude-code-security-review)
```

## Using it (POC)

1. Add the repository secret `ANTHROPIC_API_KEY`. Use a key from a dedicated Anthropic workspace with a spend limit.
2. Copy [`workflow-templates/ai-security-review.yml`](../workflow-templates/ai-security-review.yml) to `.github/workflows/` in your repository.

## When does a review run?

The central rules live in [`policy/default.yml`](policy/default.yml). They are applied in this order:

1. **Always skipped:**
   - events other than `pull_request`
   - PRs from forks
   - PRs by bots (e.g. Dependabot)
2. **Skipped** if the PR changes more than 100 files. The gate posts a PR comment (once) asking for a separate review, because the review and its comments only cover 100 files.
3. **Skipped** if an earlier review already posted security comments on the PR. Each PR gets at most one set of findings.
4. **Review** if lines were added to a dependency manifest (`package.json`, `requirements*.txt`, `go.mod`, …). This applies even under `docs/` or `tests/`.
5. **Skipped** if the PR only changes documentation or test files. For renames, both the old and new paths count.
6. **Review** if the PR changes at least 300 lines.
7. Otherwise **skipped**.

The job summary always says which rule matched, or why the review was skipped. Repositories can't change these rules. If the gate itself fails (for example, a GitHub API error), the review is skipped and a warning annotation appears on the PR's checks.

## Development

Requires Python 3.13 or later (the gate uses `PurePath.full_match`).

```sh
pip install pytest pyyaml
python -m pytest ai-security-review/gate
```

## Known limitations (POC)

- **Authentication** uses an API key secret. Workload Identity Federation will replace it.
- **The caller workflow lives in the scanned repository**, so a same-repo PR could edit it. The org ruleset delivery (phase 2) removes this.
- **Code merged without a PR isn't reviewed.** Neither are PRs from forks.
