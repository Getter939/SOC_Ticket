from django.urls import path
from django.views.generic import RedirectView

from . import views

urlpatterns = [
    path('triage_queue/', views.triage_queue, name='triage_queue'),
    path('triage_action/', views.triage_action, name='triage_action'),
    path('claim_alert/', views.claim_alert, name='claim_alert'),
    path('release_alert/', views.release_alert, name='release_alert'),
    # The Tier 2 queue moved to /incidents/tier2-queue/ on 2026-09-23 — it was
    # never Wazuh code, only born next to the alert triage queue. Unnamed on
    # purpose: reverse('escalation_queue') must resolve to the new route, and
    # this pattern only exists so an analyst's bookmark still lands. The two
    # POST endpoints get no redirect — nobody bookmarks a form action, and a
    # 301 would turn the POST into a GET.
    path('escalation_queue/', RedirectView.as_view(
        pattern_name='escalation_queue', permanent=True, query_string=True)),
]
