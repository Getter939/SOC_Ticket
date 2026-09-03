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
  and inline in `build-tier1.js`. Currently `v1.1.0` / 3 Sep 2026.
- The table of contents is a live Word field: it populates when the `.docx` is
  opened/updated in Word, and shows blank in a raw headless PDF export.
