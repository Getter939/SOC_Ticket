@echo off
REM ===========================================================================
REM  Production launch for the SOC Ticket app (Waitress behind IIS/ARR).
REM  Started by the SOCTicketWaitress NSSM service: cmd /c C:\SOCTicket\app\run-prod.cmd
REM
REM  The --trusted-proxy / --trusted-proxy-headers flags are MANDATORY: Waitress
REM  >= 2.0 clears X-Forwarded-* by default (clear_untrusted_proxy_headers=True),
REM  so without them X-Forwarded-Proto never reaches Django, SECURE_PROXY_SSL_HEADER
REM  never fires, and SECURE_SSL_REDIRECT=True 301-loops forever. Do not remove them.
REM  See docs/operations/production-deployment.windows.md Stage 9.3.
REM ===========================================================================
cd /d C:\SOCTicket\app
venv\Scripts\waitress-serve.exe --listen=127.0.0.1:8000 --threads=8 --trusted-proxy=127.0.0.1 --trusted-proxy-headers="x-forwarded-for x-forwarded-proto" config.wsgi:application
