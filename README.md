# wiz-cli

`wiz-cli` is a macOS-first command-line client for the Wiz GraphQL API. It prints JSON by default. Pass `-H` or `--human` for tables and readable labelled output.

A threat is not a separate API object. It is an Issue whose `type` is `THREAT_DETECTION`. The `threats` and `threat` commands use the same issue query and mutation engine as the issue commands. They add the type filter and request threat-detection details.

## Install

Install from Homebrew:

```console
brew install rtrompier/tap/wiz-cli
```

Install from source:

```console
cargo install --git https://github.com/rtrompier/wiz-cli
```

## Configuration

Set the credential variables in the environment before a network operation. Do not put credentials in command arguments or files.

| Variable | Required | Default |
| --- | --- | --- |
| `WIZ_CLIENT_ID` | Yes | None |
| `WIZ_CLIENT_SECRET` | Yes | None |
| `WIZ_API_URL` | Yes | None — your tenant's GraphQL endpoint, `https://api.<region>.app.wiz.io/graphql` |
| `WIZ_AUTH_URL` | No | `https://auth.app.wiz.io/oauth/token` |
| `XDG_CACHE_HOME` | No | `$HOME/.cache` |

Authentication uses the OAuth2 client credentials grant with the `wiz-api` audience.

### OAuth scopes

Grant only the scopes required by the commands the service account will run.

| Operation | Required scope |
| --- | --- |
| Read `issuesV2`, `issue`, `issueEvidenceRecords`, `issueHistoryEvents`, and `issueSuggestedAssignees` | `read:issues` and `read:threat_issues` |
| Change `OPEN` to or from `IN_PROGRESS` with `updateIssue` | `write:issue_status` |
| Ignore an issue by moving it to `REJECTED` or `RESOLVED` with `updateIssue` | `write:issue_ignore` |
| Add a note with `createIssueNote` | `write:issue_comments` |
| Assign issues with `updateIssuesAssignee` | `write:issue_participants` |

The service account needs both read scopes. `read:threat_issues` grants access to `query.issuesV2`, `query.issueEvidenceRecords`, and `query.issueHistoryEvents`; `read:issues` alone is not enough.

`write:issue_status` and `write:issue_ignore` are deliberately separate. Moving between `OPEN` and `IN_PROGRESS` changes workflow state. Moving an issue to `REJECTED` or `RESOLVED` accepts or closes a security risk and requires `write:issue_ignore`. A service account with only `write:issue_status` cannot ignore an issue.

### Token cache

The CLI caches the OAuth access token in `$XDG_CACHE_HOME/wiz-cli/token.json`. If `XDG_CACHE_HOME` is unset, it uses `$HOME/.cache/wiz-cli/token.json`. The directory has mode `0700`. The token file has mode `0600`. The CLI also corrects an existing token file with looser permissions.

The CLI reuses a token only when it has more than 60 seconds left. A corrupt or unreadable cache falls back to a fresh token request.

## Read issues and threats

List issues. `-n` defaults to 20:

```console
wiz-cli issues --severity critical --status open -n 50
```

List all threats and include threat details:

```console
wiz-cli threats --threat-runtime-program-name osascript --all
```

`threats` fixes the type to `THREAT_DETECTION`. It rejects `--type`.

Show one issue:

```console
wiz-cli issue ISSUE-123
```

Show one threat with threat details:

```console
wiz-cli threat ISSUE-123
```

List minimal evidence records:

```console
wiz-cli evidence ISSUE-123
```

List minimal history events:

```console
wiz-cli history ISSUE-123
```

Both queries are verified against a live tenant. Note that Wiz scopes them through `filterBy`, not a top-level `issueId` argument, and the two filter fields are spelled differently: `issueEvidenceRecords` takes `filterBy: { issueId }` while `issueHistoryEvents` takes `filterBy: { issue }`.

To confirm any schema yourself, `wiz-cli graphql` accepts introspection queries:

```console
wiz-cli graphql 'query { __type(name: "IssueHistoryEventFilters") { inputFields { name } } }'
```

### Filters and pagination

List-valued filters accept repeated flags, comma-separated values, or both:

```console
wiz-cli issues --severity high,critical --status open --status in_progress --project PROJECT-1
```

Enum values are case-insensitive. The CLI validates them before making a request. Date filters accept `30m`, `12h`, `7d`, and `2w` forms and convert them to absolute UTC timestamps:

```console
wiz-cli issues --since 7d --created-before 12h --resolved-since 2w
```

Use `--all` to ignore `-n` and fetch every page. The CLI requests at most 500 records per page and emits one combined JSON document.

## Update issues

Each mutation command accepts one ID, comma-separated IDs, or `-` to read newline-separated IDs from standard input.

Close an issue and add its audit note first:

```console
wiz-cli close ISSUE-123 --reason WONT_FIX --note "Risk accepted by the security review"
```

Move issues back into active work:

```console
wiz-cli status ISSUE-123,ISSUE-456 IN_PROGRESS
```

Add the same note to several issues:

```console
wiz-cli note ISSUE-123,ISSUE-456 "Investigation started"
```

Assign several issues in one API call:

```console
wiz-cli assign ISSUE-123,ISSUE-456 security-owner@example.com
```

For multi-ID `close`, `status`, and `note` operations, the CLI continues after an individual failure and exits non-zero after printing every per-ID result. Assignment is one batch mutation because the API accepts an ID list.

### Close reason mapping

Every close operation requires `write:issue_ignore`. The reason determines the target status.

| Resolution reason | Status | Applies to |
| --- | --- | --- |
| `FALSE_POSITIVE` | `REJECTED` | Non-threat issue |
| `EXCEPTION` | `REJECTED` | Non-threat issue |
| `WONT_FIX` | `REJECTED` | Non-threat issue |
| `NOT_MALICIOUS_THREAT` | `REJECTED` | Threat only |
| `SECURITY_TEST_THREAT` | `REJECTED` | Threat only |
| `PLANNED_ACTION_THREAT` | `REJECTED` | Threat only |
| `INCONCLUSIVE_THREAT` | `REJECTED` | Threat only |
| `MALICIOUS_THREAT` | `RESOLVED` | Threat only |
| `OBJECT_DELETED` | `RESOLVED` | Non-threat issue |
| `ISSUE_FIXED` | `RESOLVED` | Non-threat issue |
| `CONTROL_CHANGED` | `RESOLVED` | Non-threat issue |
| `CONTROL_DISABLED` | `RESOLVED` | Non-threat issue |
| `CONTROL_DELETED` | `RESOLVED` | Non-threat issue |
| `DETECTION_EXPIRED` | `RESOLVED` | Non-threat issue |
| `SEVERITY_CHANGED` | `RESOLVED` | Non-threat issue |

On a real close, the CLI fetches all requested issue types in one query. It rejects a threat-only reason for a non-threat issue and a non-threat reason for a threat. Dry-run skips this network validation.

`--rejection-expires-days` sets `rejectionExpiredAt` and only works with a reason that maps to `REJECTED`:

```console
wiz-cli close ISSUE-123 --reason EXCEPTION --rejection-expires-days 90
```

When `--note` is present, the CLI creates the note before it changes status. If note creation fails, it leaves that issue open.

### Batch from a listing

Pipe newline-separated IDs into a bulk close:

```console
wiz-cli issues --status open --severity critical --all \
  | jq -r '.nodes[].id' \
  | wiz-cli close - --reason WONT_FIX --note "Bulk risk review completed"
```

Blank input lines are ignored. An empty standard input is an error.

### Dry-run

Every mutating command supports `--dry-run`. It prints the exact GraphQL query and variables in execution order. JSON output is an array of objects with `query` and `variables`. `-H` prints labelled queries and pretty variables.

Dry-run needs no credentials. It does not read or write the token cache and does not use the network.

```console
wiz-cli close ISSUE-123 --reason WONT_FIX --note "Review note" --dry-run
wiz-cli status ISSUE-123 OPEN --dry-run
wiz-cli note ISSUE-123 "Review note" --dry-run
wiz-cli assign ISSUE-123 owner@example.com --dry-run
```

## Escape hatch and identity

Run a raw GraphQL query with optional variables:

```console
wiz-cli graphql 'query CurrentIssues($first: Int) { issues: issuesV2(first: $first) { totalCount } }' --vars '{"first":1}'
```

Inspect the service account identity, scopes, audience, issuer, expiry, and remaining lifetime without calling GraphQL:

```console
wiz-cli whoami -H
```

`whoami` fetches or reuses an OAuth token and decodes its JWT payload locally. It never prints the access token. It reports the subject, email, tenant, data center and expiry.

It cannot list your granted scopes. Wiz packs permissions into an opaque `encodedScopes` bitmask with no public decoding table, so the scope list always comes back empty. Read the granted scopes in the Wiz UI on the service account, or probe a command and read the error Wiz returns.
