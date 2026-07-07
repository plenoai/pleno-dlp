# Licensing

pleno-dlp uses **standard SPDX licenses, one per distributable artifact**.
There is no per-file or per-directory license split inside any repository —
that keeps the boundary auditable and avoids a bespoke, hard-to-reason-about
license scheme.

## This repository — AGPL-3.0-only

Everything in `plenoai/pleno-dlp` (the scan engine, detectors, source
connectors, CLI, and output formatters) is licensed under
**AGPL-3.0-only** (`SPDX-License-Identifier: AGPL-3.0-only`). The full
text is in [`LICENSE`](../LICENSE). One license covers the whole tree; the
single Go module compiles to a single AGPL binary.

## Benchmark and rule data — Apache-2.0, in its own repository

The falsifiable-evidence assets — fixtures, the fixture generator,
adjudication labels, and benchmark data — are the reusable, reproducible
core of the moat and must be usable **without AGPL network-copyleft
obligations**. Rather than mixing a second license into this AGPL tree,
they live in a **separate repository, `dlp-bench`, licensed Apache-2.0 at
its root** (`SPDX-License-Identifier: Apache-2.0`). See #298 for its
publication.

The same principle applies to any detection **rules** we later extract
from Go code into a standalone data format (e.g. a portable rule pack):
if and when that happens, the rule data ships in its own Apache-2.0
artifact, never as an in-tree exception here.

Rule of thumb: **if an asset is meant to be freely reused and reproduced,
it gets its own repository under Apache-2.0; if it is the AGPL engine, it
stays here.** No third license, no in-tree exceptions.

## No-rug-pull pledge

We pledge **not to relicense the AGPL engine to a proprietary or
source-available license.** The Contributor License Agreement (below)
gives the maintainers the legal *option* to relicense, but this pledge is
a public commitment not to exercise it as a rug pull. The commitment — not
the retained option — is the trust signal.

Concretely:

- Every tagged release stays under the license it shipped with. AGPL
  releases remain AGPL forever; relicensing (if it ever happened) could
  only apply going forward, never retroactively.
- If this pledge is ever broken, the last AGPL-licensed commit remains
  AGPL and forkable by anyone.

## Contributor License Agreement (CLA)

Contributions to this repository require agreeing to the
[Contributor License Agreement](CLA.md). The CLA lets us accept
contributions cleanly and preserves the relicensing *option* that the
no-rug-pull pledge above commits us not to abuse.

The CLA is checked automatically on pull requests. See
[`CLA.md`](CLA.md) for the text and how to sign.
