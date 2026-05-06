---
name: secret-scanner-orchestrator
description: Coordinates the five-agent team for pleno-dlp (architect, detector-engineer, connector-engineer, core-engineer, qa) when work spans detectors, sources, engine, CLI, output, or release. Trigger when the user asks to add or modify detectors or sources, change interfaces, change engine/CLI/output, work on the release pipeline, or follows up with phrases like "rerun", "redo", "patch", "improve based on the previous run", "just the <area>". Do not trigger for one-line greps or pure factual questions about the repo — answer those directly.
---

# secret-scanner-orchestrator

## Purpose

Drive every meaningful change in pleno-dlp (detector or source additions, interface revisions, engine/CLI/output changes, release work) through the five-agent team, while keeping trufflehog-compatible detector interfaces and our reimplemented source connectors aligned.

## Execution mode

**Agent team (default).** Bind all five agents into a team via `TeamCreate`, distribute work via `TaskCreate`, and let teammates coordinate directly with `SendMessage`.

Exception: a single-detector addition with no interface impact may run in **subagent mode** by calling detector-engineer alone — team overhead is not worth it for such a narrow scope.

## Phase 0: context check

At workflow start:

1. Look for `_workspace/` at the repo root.
   - **Exists + user requested partial change** → partial rerun. Invoke only the owning agent.
   - **Exists + user provided new input** → archive `_workspace/` to `_workspace_prev/` and start fresh.
   - **Missing** → first run. Create `_workspace/`.
2. If `git status` is dirty, branch off via `gh wt` before continuing.

## Phase 1: classify the request

Map the request to one of:

| Class | Owner | Collaborators |
|---|---|---|
| Add 1–N detectors | detector-engineer | qa (e2e validation) |
| Add 1–N sources | connector-engineer | core-engineer (registry), qa |
| Interface change (Detector / Source / Result / Chunk) | architect → detector-engineer + connector-engineer | core-engineer, qa |
| CLI / engine / output change | core-engineer | qa |
| Release / CI / dependency | architect | (broadcast notice to team) |
| Regression fix | qa report → owning agent | architect (when infra is the cause) |

## Phase 2: form the team and assign work

1. `TeamCreate(team_name="secret-scanner", members=["architect", "detector-engineer", "connector-engineer", "core-engineer", "qa"])`.
2. Decompose into tasks via `TaskCreate`. Express dependencies with `addBlockedBy`.
3. Assign owners explicitly.

Default dependency patterns:
- Interface change → architect decides signature → detector-engineer + connector-engineer update in parallel → core-engineer adapts engine → qa validates.
- New detector → detector-engineer implements → core-engineer confirms registration → qa runs e2e.

## Phase 3: monitor and integrate

- Teammates update via `TaskUpdate`. If no progress for 30 min, ping with SendMessage.
- Persist deliverables to `_workspace/<phase>_<owner>_<artifact>.md`.
- qa regression reports route immediately back to the owning agent.

## Phase 4: wrap up

1. qa publishes a final pass (e2e + race) at `_workspace/qa-report-<date>.md`.
2. Synthesise `_workspace/` notes into a one-line PR title and a value-first body.
3. Append to the CLAUDE.md change-history table (which agent drove which change).
4. `TeamDelete` to release the team.

## Data transfer protocol

| Channel | Mechanism |
|---|---|
| Work coordination | `TaskCreate` / `TaskUpdate` |
| Real-time chat | `SendMessage` (1–2 sentences, decisions only) |
| Deliverables | `_workspace/<phase>_<owner>_<artifact>.md` for prose; code under `pkg/...` |
| Interface decisions | `_workspace/architecture-decisions.md` (append-only ADR log) |

## Error handling

- One agent fails: retry once. Second failure → continue without that result and note the gap.
- Interface mismatch (e.g. detector-engineer and connector-engineer assume different signatures): architect is the tiebreaker; both sides realign to the architect's call.
- qa reports the same regression twice: ban the quick fix. Write an ADR identifying the root cause before any further patch.

## Team-size sanity

Five agents fits the "large" tier. All five engage on interface changes; smaller asks (a single detector) compress to detector-engineer + qa.

## Test scenarios

**Happy path:** "Add Slack bot token detector" → tasks: detector-engineer (implement) → core-engineer (registry check) → qa (e2e fixture). PR draft within 30 minutes.

**Failure path:** detector-engineer adopts a non-standard signature → connector-engineer's task fails compilation → orchestrator pulls in architect → ADR written → both sides redo → qa validates → green.
