# Codex Handoff — RCA Workflow Redesign (Phase 3B)

> Continues `docs/CODEX_HANDOFF_PHASE_3.md`. Phase 3 (Codex's RCA workspace) is done; this session
> **redesigned the analyst journey** on top of it. Code is written, tested and Ruff-clean, but the
> **browser / session-timeout QA is not done** — that is the first task below.
> **[V]** = verified this session. **[ ]** = still to do.

---

## 1. Why this change

The RCA feature worked but the analyst's journey was fragmented: the email and ticket page sent
them to the generic subtask form (tiny status dropdown + a stray file upload), nothing told them to
start, the workspace had no case context, and unsaved typing could be lost to the 30-minute idle
logout. This session made the **workspace the single place an analyst works an RCA**, with a clear
start, the case on hand, and protection against idle logout. Approved decisions and full detail are
in the plan: `~/.claude/plans/c-users-nt-desktop-report-soc-rca-20260-tidy-goblet.md`.

## 2. Repo state

- **[V]** Branch `main`, HEAD `0bd9d7e` ("15/9 RCA Report template adjustment + Project Incident
  Feature improvement"). Phases 1–2 are committed.
- **[V]** Everything below is **uncommitted** (owner commits himself — do **not** commit/push).
  The working tree also still contains **Codex's Phase 3** (untracked `apps/incidents/rca_views.py`
  and the RCA templates) and an unrelated **acting-tier** `CHANGELOG.md` edit — keep those
  separate if you ever stage.

## 3. What this session changed

Start flow, case panel, idle keep-alive, and the ticket-page cleanup, plus one bug fix.

| Area | Files | What |
|---|---|---|
| Start action | `apps/incidents/rca.py` (`start_rca`, `case_number_for`), `rca_views.py` (`rca_start`, `_load_workspace` no longer auto-creates on OPEN, `_workflow_step`, `is_open`/`case`/`idle_seconds` in context), `urls.py` (`rca_start` route) | "เริ่มจัดทำ RCA" button; opening an OPEN request creates nothing |
| Workspace UI | `templates/incidents/rca_workspace.html` | Start card, header stepper (start→build→draft→deliver), case-panel include, keep-alive include (editors only) |
| Case panel | `apps/incidents/selectors.py` (`get_rca_case_context`), new `templates/incidents/_rca_case_panel.html` | Read-only collapsible ticket snapshot: fields, IOCs, alerts, evidence |
| Ticket-page row | `apps/incidents/selectors.py` (`subtask.rca_can_start`), `templates/incidents/ticket_detail.html` | RCA rows show only a workspace button; the inline status/upload form is hidden for RCA (kept for VA/PT, InfraSec, internal) |
| Email links | `apps/incidents/notifications.py` (`_request_url`), `models.py` (`PLACEHOLDERS` gain `request_url`) | `notify_response_request_created` **and** `notify_response_request_completed` link to the RCA workspace for `FORENSIC_RCA`, else the ticket. Triggers unchanged; `_render` tolerates the extra key so custom DB templates still send |
| Session keep-alive | `apps/accounts/views.py` (`session_keepalive`), `apps/accounts/urls.py`, new `templates/includes/_session_keepalive.html` | `@login_required @require_GET` JSON endpoint; the partial pings while the user is active (≤ once/5 min) and shows a 2-minute countdown modal before idle expiry. Reusable |
| IOC 500 fix | `apps/incidents/models.py` (`RCAIndicator.normalize_value` classmethod), `forms.py` (`RCAIndicatorForm.clean_value`), `rca_views.py` (IOC save `except IntegrityError`) | A within-category duplicate that only collides after normalisation (e.g. upper/lower-case hash) is now a form error, not a 500 |

### Bug fixed in Codex's Phase 3 (important)
`rca_views.rca_final_submission` read `previous_status` / `previous_notes` / `was_done` **after**
`SubtaskUpdateForm.is_valid()`. `is_valid()`'s `_post_clean` writes the submitted values onto the
same `subtask` instance, so `was_done` looked `True` and the **completion email to SOC Managers was
silently skipped** (and the audit diff was wrong). Fixed by snapshotting before building the form.
A regression test now covers it.

## 4. Verified this session
- **[V]** `python -m ruff check apps/incidents apps/accounts` — clean.
- **[V]** `manage.py makemigrations --check --dry-run` — no migration (only Python-constant and
  behaviour changes).
- **[V]** `manage.py check` — no issues.
- **[V]** `manage.py test apps.incidents` — **823 pass, 1 fail**: the failure is the long-standing
  baseline `AttachmentWorkflowPermissionTest.test_detail_page_shows_attachment_accountability_metadata`
  ("Uploaded by"), unrelated to this work and failing on clean HEAD.
- New tests added: RCA start flow (open shows Start card + creates nothing; start creates/prefills +
  In Progress + one audit row; idempotent; refused for non-editors/frozen), case panel, stepper,
  normalized-duplicate IOC, keep-alive endpoint + workspace wiring, completion email on workspace
  Mark Done, "save without complete sends nothing", created-email URL (RCA→workspace, VA/PT→ticket,
  custom `{ticket_url}` template still sends). `ResponseTeamUiTest.test_assignee_sees_update_form_and_can_complete`
  moved to a VA/PT request; a new test asserts the RCA row shows the workspace button and not the form.

## 5. NOT done — start here

1. **[ ] Browser QA** (`SOC Ticket` launch config; force-login a Forensic account — never guess
   passwords, per the live-DB recipe). Walk: Response Requests queue → workspace → **Start** →
   case panel expands and shows the ticket's IOCs/alerts/evidence → fill a section → generate a
   draft → upload the final → **Mark Done** → workspace goes read-only. Confirm the console has no
   CSP errors (the workspace and keep-alive scripts must run — they carry `request.csp_nonce`).
2. **[ ] Keep-alive real-timing QA.** Temporarily set `SESSION_IDLE_MINUTES=3` in `.env`; confirm:
   typing keeps the session alive; going idle shows the countdown modal ~2 min before expiry;
   "อยู่ในระบบต่อ" resets it; letting it lapse shows the expired state. **Restore `.env` after.**
   Watch for a Bootstrap-modal issue: the partial builds `new bootstrap.Modal(...)`; it guards on
   `typeof bootstrap`, but confirm the bundle is loaded before the inline script on this page.
3. **[ ] Email link QA.** Console email backend: spawn an RCA request (as SOC Manager) → the
   analyst's email links to the workspace; Mark Done → the managers' email links to the workspace.
4. **[ ] CHANGELOG** — plan step 8 was not done. Add an Unreleased entry for the redesigned RCA
   analyst flow, kept separate from the acting-tier entry already in the working tree.
5. **[ ] Ticket-form reuse (optional).** `_session_keepalive.html` is generic; the plan leaves it on
   the workspace only. Reusing it on `ticket_form.html` is deferred.

## 6. Risks / notes
- **Unsaved work across section switches is warn-only** (a `beforeunload`/confirm), not retained —
  this was the user's explicit choice; do not add autosave without asking.
- The keep-alive **cannot** save half-typed rows; it only prevents the logout. That is by design.
- `_load_workspace` now creates the `RCAReport` only when the user can edit **and** the request is
  past OPEN. A read-only viewer, or anyone on an OPEN request, sees the case panel + a waiting/Start
  notice and no report is created. If you change this, re-check `rca_start` and the section-POST
  paths (they 403 when `report is None`).
- `RequireMFAMiddleware` gates the keep-alive endpoint (auth + MFA). An expired session 302s to
  login, which the JS reads as "expired" — intended.

## 7. Commands
```powershell
.\venv\Scripts\python.exe manage.py test apps.incidents.test_rca apps.incidents.test_ui_smoke --keepdb --noinput
.\venv\Scripts\python.exe manage.py test apps.incidents --keepdb --noinput   # 1 expected baseline failure
.\venv\Scripts\python.exe -m ruff check apps/incidents apps/accounts
.\venv\Scripts\python.exe manage.py runserver 8088 --settings=config.settings_local
```

## Recommended first task
Do the **browser + keep-alive QA (§5.1–§5.3)**. The Python paths are covered by tests; the real
risk is now the rendered flow — the Start button, the case panel, the stepper, and especially the
keep-alive modal timing and CSP. Fix anything that surfaces, then add the CHANGELOG entry (§5.4).
