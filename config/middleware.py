"""Custom security middleware for the SOC ticketing app."""

from django.conf import settings


class ContentSecurityPolicyMiddleware:
    """Add a Content-Security-Policy header to every response.

    Defense-in-depth against XSS, clickjacking, and data exfiltration. The
    policy string lives in ``settings.CONTENT_SECURITY_POLICY`` so it can be
    tuned per environment.

    Current policy keeps ``'unsafe-inline'`` for scripts/styles because the
    templates rely on inline ``<script>``/``<style>`` blocks and a couple of
    inline event handlers. The high-value directives are still enforced:
    ``default-src 'self'`` plus a single-CDN allowlist (so an injected
    ``<script src=//attacker/x.js>`` is blocked), ``object-src 'none'``,
    ``base-uri 'self'``, ``form-action 'self'`` (blocks form-based
    exfiltration), and ``frame-ancestors 'none'`` (clickjacking).

    Recommended next step: tighten ``script-src`` to a per-request nonce and
    drop ``'unsafe-inline'`` — only two inline handlers
    (ticket_detail.html, ticket_history.html) need refactoring first.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.policy = getattr(settings, 'CONTENT_SECURITY_POLICY', '')
        self.report_only = getattr(settings, 'CONTENT_SECURITY_POLICY_REPORT_ONLY', False)
        self.header = (
            'Content-Security-Policy-Report-Only'
            if self.report_only else 'Content-Security-Policy'
        )

    def __call__(self, request):
        response = self.get_response(request)
        if self.policy and not response.has_header(self.header):
            response[self.header] = self.policy
        return response
