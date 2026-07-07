"""Custom security middleware for the SOC ticketing app."""

import secrets

from django.conf import settings

# Token in the policy string (settings.CONTENT_SECURITY_POLICY) that this
# middleware swaps for a fresh per-request nonce before emitting the header.
NONCE_PLACEHOLDER = '{NONCE}'


class ContentSecurityPolicyMiddleware:
    """Add a Content-Security-Policy header to every response.

    Defense-in-depth against XSS, clickjacking, and data exfiltration. The
    policy string lives in ``settings.CONTENT_SECURITY_POLICY`` so it can be
    tuned per environment.

    ``script-src`` is nonce-based: this middleware mints a fresh random nonce
    per request, exposes it as ``request.csp_nonce`` (templates stamp it on
    every inline ``<script nonce="{{ request.csp_nonce }}">``), and substitutes
    it into the policy. ``'unsafe-inline'`` is therefore dropped from
    ``script-src`` — an injected inline ``<script>`` without the unguessable
    nonce is refused by the browser. (Inline ``on*=`` handlers are likewise
    refused, so the templates use ``addEventListener`` instead.)

    ``style-src`` still allows ``'unsafe-inline'``: inline ``style=`` attributes
    are pervasive across the Bootstrap templates and cannot carry a nonce. The
    other high-value directives are enforced too: ``default-src 'self'`` plus a
    single-CDN allowlist, ``object-src 'none'``, ``base-uri 'self'``,
    ``form-action 'self'``, and ``frame-ancestors 'none'``.
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
        # Mint the nonce before the view/template renders so inline scripts can
        # stamp the matching value via {{ request.csp_nonce }}.
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce
        response = self.get_response(request)
        if self.policy and not response.has_header(self.header):
            response[self.header] = self.policy.replace(NONCE_PLACEHOLDER, nonce)
        return response
