"""
Pulls Wazuh alerts (rule.level >= min_level) from OpenSearch and stores them
as WazuhAlert rows.

Rules
─────
• Never raises on connection / HTTP failure — caught, logged, returned in
  the result dict's 'errors' list.
• Per-record parsing errors are caught individually and logged — one bad
  alert must not abort the whole batch.
• A single-row IngestWatermark tracks the last ingested @timestamp so that
  repeat runs only fetch new alerts. The watermark only advances after a
  successful write.
• The @timestamp range filter is >=gte<= (never >gt<): several alerts can share
  one timestamp, and a batch cut can land mid-group, so the boundary timestamp
  must be re-fetched — the unique opensearch_id makes re-ingestion a no-op.
  Bursts larger than one batch are drained by paginating within the run
  (see fetch_and_store_alerts).
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

import requests

from .models import IngestWatermark, WazuhAlert

logger = logging.getLogger(__name__)

ALERTS_INDEX = 'wazuh-alerts-*'


def _opensearch_url():
    return f'https://{settings.OPENSEARCH_HOST}:{settings.OPENSEARCH_PORT}/{ALERTS_INDEX}/_search'


def _get_watermark():
    watermark, _ = IngestWatermark.objects.get_or_create(pk=1)
    return watermark


def _build_query(min_level, since, batch_size, exclude_ids=None):
    # >=gte<= on @timestamp, never >gt<: several alerts can share the boundary
    # timestamp and a previous batch may have stored only some of them, so the
    # boundary must be re-fetched (opensearch_id dedup makes that a no-op).
    # ``exclude_ids`` lets the pagination loop skip docs already fetched at
    # ``since`` this run, so a timestamp group larger than batch_size still
    # drains instead of returning the same full page forever.
    query = {
        'query': {
            'bool': {
                'filter': [
                    {'range': {'rule.level': {'gte': min_level}}},
                    {'range': {'@timestamp': {'gte': since.isoformat()}}},
                ]
            }
        },
        'size': batch_size,
        'sort': [{'@timestamp': 'asc'}],
    }
    if exclude_ids:
        query['query']['bool']['must_not'] = [{'ids': {'values': list(exclude_ids)}}]
    return query


def _parse_hit(hit):
    """Convert a raw OpenSearch hit into kwargs for WazuhAlert. Raises on bad data."""
    source = hit['_source']
    rule = source.get('rule', {})
    agent = source.get('agent', {})
    mitre = rule.get('mitre', {})
    data = source.get('data', {})
    decoder = source.get('decoder', {})

    timestamp = parse_datetime(source['@timestamp'])
    if timestamp is None:
        raise ValueError(f"Could not parse @timestamp: {source.get('@timestamp')!r}")

    return dict(
        opensearch_id=hit['_id'],
        alert_id=str(source.get('id', '')),
        timestamp=timestamp,
        agent_id=agent.get('id', ''),
        agent_name=agent.get('name', ''),
        agent_ip=agent.get('ip') or None,
        rule_id=str(rule.get('id', '')),
        rule_level=rule.get('level', 0),
        rule_description=rule.get('description', ''),
        rule_groups=rule.get('groups', []) or [],
        mitre_techniques=mitre.get('technique', []) or [],
        mitre_tactics=mitre.get('tactic', []) or [],
        mitre_ids=mitre.get('id', []) or [],
        raw_data=data or {},
        decoder_name=decoder.get('name', ''),
    )


def store_alert_hits(hits, min_level=10, advance_watermark=True):
    """
    Parse and store OpenSearch hit dictionaries.

    Offline fixtures disable watermark updates so demo timestamps cannot
    affect the next production OpenSearch fetch.
    """
    result = {'fetched': len(hits), 'created': 0, 'skipped': 0, 'errors': []}
    new_alerts = []
    newest_timestamp = None

    for hit in hits:
        try:
            source = hit['_source']
            rule_level = int(source.get('rule', {}).get('level', 0))
            if rule_level < min_level:
                result['skipped'] += 1
                continue

            opensearch_id = hit['_id']
            if WazuhAlert.objects.filter(opensearch_id=opensearch_id).exists():
                result['skipped'] += 1
                continue

            kwargs = _parse_hit(hit)
            new_alerts.append(WazuhAlert(**kwargs))
            if newest_timestamp is None or kwargs['timestamp'] > newest_timestamp:
                newest_timestamp = kwargs['timestamp']
        except Exception as exc:
            msg = f"Failed to parse alert {hit.get('_id', '?')}: {exc}"
            logger.error(msg)
            result['errors'].append(msg)

    if new_alerts:
        try:
            created = WazuhAlert.objects.bulk_create(new_alerts, ignore_conflicts=True)
            result['created'] = len(created)
        except Exception as exc:
            msg = f'Bulk create failed: {exc}'
            logger.error(msg)
            result['errors'].append(msg)
            return result

    if advance_watermark and newest_timestamp is not None:
        watermark = _get_watermark()
        if watermark.last_timestamp is None or newest_timestamp > watermark.last_timestamp:
            watermark.last_timestamp = newest_timestamp
            watermark.save(update_fields=['last_timestamp', 'updated_at'])

    return result


def _hit_timestamp(hit):
    """Parsed @timestamp of a hit, or None if missing/unparseable."""
    raw = hit.get('_source', {}).get('@timestamp')
    return parse_datetime(raw) if raw else None


def fetch_and_store_alerts(min_level=10, batch_size=500, max_pages=20):
    """
    Fetch new Wazuh alerts (rule.level >= min_level) from OpenSearch and
    store them as WazuhAlert rows.

    Paginates within the run: a burst larger than ``batch_size`` is drained
    page by page (each page is stored — and the watermark advanced — before
    the next fetch), up to ``max_pages`` pages per run. Anything beyond that
    is picked up by the next run via the watermark, so nothing is lost.

    Each page advances a local ``since`` cursor to the page's newest
    @timestamp and re-queries with >=gte<= while excluding the doc ids already
    fetched at that boundary timestamp — so alerts sharing one timestamp are
    never skipped, even when a whole timestamp group exceeds ``batch_size``.

    Returns: {'fetched': N, 'created': N, 'skipped': N, 'errors': [str, ...]}
    """
    totals = {'fetched': 0, 'created': 0, 'skipped': 0, 'errors': []}

    watermark = _get_watermark()
    since = watermark.last_timestamp
    if since is None:
        since = timezone.now() - timedelta(hours=24)
    boundary_ids = []   # doc ids already fetched at exactly ``since`` this run

    for _page in range(max_pages):
        query = _build_query(min_level, since, batch_size, exclude_ids=boundary_ids)

        try:
            response = requests.post(
                _opensearch_url(),
                json=query,
                auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
                verify=settings.OPENSEARCH_CA_BUNDLE or settings.OPENSEARCH_VERIFY_SSL,
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            msg = f'OpenSearch request failed: {exc}'
            logger.error(msg)
            totals['errors'].append(msg)
            return totals

        hits = payload.get('hits', {}).get('hits', [])
        if not hits:
            break

        page_result = store_alert_hits(hits, min_level=min_level, advance_watermark=True)
        totals['fetched'] += page_result['fetched']
        totals['created'] += page_result['created']
        totals['skipped'] += page_result['skipped']
        totals['errors'].extend(page_result['errors'])

        if len(hits) < batch_size:
            break   # short page — the queue is drained

        # Full page: advance the cursor to the page's newest timestamp. If the
        # whole page shares ``since`` (one huge timestamp group), keep the
        # cursor and grow the exclusion list instead so the next page fetches
        # the rest of the group.
        newest = max((ts for ts in map(_hit_timestamp, hits) if ts), default=None)
        if newest is None:
            msg = 'Pagination stopped: full page with no parseable @timestamp.'
            logger.error(msg)
            totals['errors'].append(msg)
            break
        if newest > since:
            since = newest
            boundary_ids = [
                hit['_id'] for hit in hits if _hit_timestamp(hit) == newest
            ]
        else:
            boundary_ids.extend(hit['_id'] for hit in hits)
    else:
        logger.warning(
            'Wazuh ingest stopped after %d pages (batch_size=%d); remaining '
            'alerts will be picked up by the next run via the watermark.',
            max_pages, batch_size,
        )

    return totals
