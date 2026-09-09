"""HTTP boundaries for the IOC Database. Forensic/superuser only; ticket permissions
stay unchanged."""

import csv
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_POST

from .forms import AnalystIOCImportForm
from .ioc_values import TICKET_CATEGORY_CHOICES
from .models import AnalystIOCImport
from .ti_platform import (
    HEADERS, build_ioc_database, can_manage_inventory, import_inventory,
    remove_analyst_ioc, set_review_status,
)

logger = logging.getLogger(__name__)


def _require_manager(user):
    if not can_manage_inventory(user):
        raise PermissionDenied


def _safe_next(request):
    """Redirect target after a POST — back to the same filtered/paged view."""
    nxt = request.POST.get('next', '')
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        return nxt
    return reverse('ioc_database')


def _database_page(request, form=None, status=200):
    query = (request.GET.get('q') or '').strip()[:255]
    status_filter = request.GET.get('status', 'all')
    source_filter = request.GET.get('source', 'all')
    category_filter = request.GET.get('category', 'all')
    rows, counts = build_ioc_database(query, status_filter, source_filter, category_filter)
    return render(request, 'incidents/ioc_database.html', {
        'form': form if form is not None else AnalystIOCImportForm(),
        'query': query,
        'status_filter': status_filter,
        'source_filter': source_filter,
        'category_filter': category_filter,
        'category_choices': TICKET_CATEGORY_CHOICES,
        'counts': counts,
        'database': Paginator(rows, 30).get_page(request.GET.get('page')),
        'imports': Paginator(AnalystIOCImport.objects.select_related('uploaded_by'), 10)
                   .get_page(request.GET.get('ip')),
        'current_path': request.get_full_path(),
    }, status=status)


@login_required
@require_GET
def ioc_database(request):
    _require_manager(request.user)
    return _database_page(request)


@login_required
@require_POST
def ioc_status_toggle(request):
    """Set the FA's Checked / Not-Checked review status for one indicator."""
    _require_manager(request.user)
    try:
        set_review_status(
            request.POST.get('category', ''),
            request.POST.get('value', ''),
            request.POST.get('checked') == '1',
            request.user,
        )
    except ValidationError as exc:
        messages.error(request, '; '.join(exc.messages))
    return redirect(_safe_next(request))


@login_required
@require_POST
def analyst_ioc_remove(request):
    """Soft-remove a mistakenly uploaded analyst IOC."""
    _require_manager(request.user)
    try:
        pk = int(request.POST.get('pk', ''))
    except (TypeError, ValueError):
        raise Http404
    if remove_analyst_ioc(pk, request.user):
        messages.success(request, 'ลบรายการ IOC ที่อัปโหลดแล้ว / Removed the uploaded IOC.')
    return redirect(_safe_next(request))


@login_required
@require_POST
def ioc_database_import(request):
    _require_manager(request.user)
    form = AnalystIOCImportForm(request.POST, request.FILES)
    if form.is_valid():
        try:
            batch = import_inventory(form.cleaned_data['file'], request.user)
        except ValidationError as exc:
            form.add_error('file', exc)
        except Exception:
            logger.exception('Analyst IOC import failed')
            form.add_error('file', 'Import failed; no IOC rows were saved. Please retry.')
        else:
            messages.success(request, f'Imported {batch.row_count} rows: {batch.added_count} added, {batch.skipped_count} duplicates skipped.')
            return redirect('ioc_database')
    return _database_page(request, form, status=400)


@login_required
@require_GET
def ioc_database_template(request):
    _require_manager(request.user)
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="ioc-upload-template.csv"'
    response.write('﻿')
    csv.writer(response).writerow(HEADERS)
    return response


@login_required
@require_GET
def analyst_ioc_download(request, pk):
    _require_manager(request.user)
    batch = get_object_or_404(AnalystIOCImport, pk=pk)
    try:
        response = FileResponse(batch.file.open('rb'), as_attachment=True, filename=batch.original_name)
    except FileNotFoundError:
        raise Http404
    response['X-Content-Type-Options'] = 'nosniff'
    return response
