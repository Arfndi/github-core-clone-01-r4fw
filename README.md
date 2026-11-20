# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Arfndi/github-core-clone-01-r4fw/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Arfndi/github-core-clone-01-r4fw/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single Node.js file (`main.ts`), standard
library only — no git binary, no network access at runtime.

## What it serves

- **Git smart HTTP** (`/<owner>/<repo>.git`): protocol v2 (advertisement,
  `ls-refs`, `fetch` with shallow/deepen) and v0 (advertisements, fetch,
  receive-pack). PACK v2 read/write with plain objects; incoming deltas are
  resolved against the pack and the store. Pushes enforce fast-forward rules
  and answer with a sideband-framed report-status stream.
- **REST v3** (`/api/v3`): repositories, branches, commits, git refs,
  contents (create / read / update / delete with stale-sha detection),
  issues, labels, comments, pull requests (create, list, files, squash
  merge with three-way conflict detection).
- **GraphQL v4** (`/api/graphql`): `viewer`, `repository` (fields,
  issues with cursor pagination, pull requests), `node(id:)` global ids,
  `__type` introspection, and the `createIssue`, `closeIssue`,
  `createPullRequest`, `mergePullRequest`, `addComment` mutations. Batched
  operation documents answer in order; an unknown field is a 200 with an
  `errors` array.
- **MCP** (`/mcp`): `server/discover` (2026-07-28), the legacy `initialize`
  handshake, `tools/list`, and `tools/call` for six tools
  (`create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`).

## Running

```sh
MAKEFUN_SHOP_TOKEN=<trial token> MAKEFUN_ENV_URL=http://127.0.0.1:18080 node main.ts
```

The entry binds an ephemeral port, registers it with the environment,
answers `GET /healthz`, then polls the environment's `/done` until the
trial ends and exits. With no `MAKEFUN_ENV_URL` set it serves until killed,
which is handy for a smoke test. The viewer login is the trial token
owner's; the bearer token comes from `MAKEFUN_SHOP_TOKEN`
(default `bench-token-123` for local trials).

## Design notes

- Everything is in memory: one content-addressed object store, one
  repository record per repo. Deterministic by construction — server-made
  commits use a fixed timestamp and identity, ids come from counters, and
  the state export never sees a clock or a port.
- Hot paths are cached and invalidated on mutation: precomputed issue JSON
  strings (the read workload serves them verbatim), git advertisements,
  ls-refs answers, and fetch responses keyed by wants/haves/shallow/depth.
- Pack inflation uses a guarded single-inflate fast path: one `inflateSync`,
  then the stream end is found by its Adler-32 trailer — valid only when
  that trailer occurs exactly once in the rest of the pack; otherwise each
  occurrence is tried until one inflates cleanly. Adler-32 itself defers
  the modulo over 5552-byte blocks.
- A `PATCH` to a repository clears its git cache: changing
  `default_branch` moves the symref HEAD target, so a stale advertisement
  would serve the old default.
- Merges are real three-way merges against the merge-base. A path changed
  on both sides to different contents is a conflict (HTTP 405); anything
  else applies cleanly and lands one squash commit on the base branch.
