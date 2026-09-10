# Role manual build scripts

Generators for the per-role Thai user manuals (`../user-manual-*.th.docx`).
Each manual is a Word `.docx` built with [docx-js](https://docx.js.org/).

## Layout

- `common.js` — shared design system (TH Sarabun New, navy/blue palette, callouts,
  screenshot placeholders, styled tables) and the `buildManual()` assembler
  (cover, dynamic TOC, running header/footer). Edit this to restyle **all** manuals.
- `build-tier1.js` — the Tier 1 manual (self-contained: it predates `common.js` and
  carries its own copy of the helpers). The other scripts `require('./common')`.
- `build-tier2.js`, `build-manager.js`, `build-admin.js`, `build-owner.js`,
  `build-exec.js`, `build-response-teams.js` (Forensic + Red Team Manager) — one
  script per persona; content only.

`build-response-teams.js` builds **two** manuals from one shared body, forked on
`readsAllTickets`: the Forensic Analyst reads every ticket (read-only, v1.3.1) and
owns the IOC Database section; the Red Team Manager sees only tickets carrying a
request assigned to them. Its section numbers are counted (`SH()`), not hardcoded,
so a role-specific section renumbers the rest automatically. Because it builds two
manuals in one process it calls `resetFigures()` per body — without it the second
manual's first figure is numbered `3-2`.

## Build

```bash
npm install docx          # only dependency; not vendored here
node build-tier1.js        # writes ../user-manual-soc-analyst-tier1.th.docx
node build-tier2.js        # ...etc
```

## Screenshots

Every figure is a dashed placeholder box carrying a hidden `SHOT: <id>` tag
(e.g. `SHOT: T1-wazuh-triage`). Those ids are the capture checklist for the
images-later pass. To drop real images in, embed them via `ImageRun` in place of
the `shot()` placeholder (see `shot()` in `common.js`), then rebuild.

## Notes

- Cover version string and date are set in `common.js` (`buildManual`, cover block)
  and inline in `build-tier1.js` — **two places, keep them in step**. Currently
  `v1.4.0` / 10 Sep 2026 (manual edition 1.1).
- Content is written against
  [`docs/architecture/ticket-lifecycle-states.md`](../../../architecture/ticket-lifecycle-states.md),
  which is the authority for the state machine. When a release changes the workflow,
  diff that file first, then the manuals — the 2026-09-10 audit found the Tier 1
  manual still teaching "an Event closes the ticket immediately", two months after
  that stopped being true.
- **Not yet covered:** ticket cancellation (unreleased at the time of writing). When
  it ships it needs a pass across manager, tier1/tier2, response-teams and exec.
- The table of contents is a live Word field: it populates when the `.docx` is
  opened/updated in Word, and shows blank in a raw headless PDF export.
