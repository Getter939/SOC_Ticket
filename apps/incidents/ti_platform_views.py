"""HTTP boundaries for the IOC Database. Forensic/superuser only; ticket permissions
stay unchanged."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_POST

from .forms import ManualIOCEditForm, ManualIOCFormSet
from .ioc_values import INVENTORY_CATEGORY_CHOICES, TICKET_CATEGORY_CHOICES
from .ti_platform import (
    build_ioc_database, can_manage_inventory, create_manual_iocs,
    remove_analyst_ioc, set_note, set_review_status, update_manual_ioc,
)


def _require_manager(user):
    if not can_manage_inventory(user):
        raise PermissionDenied


def _safe_next(request):
    """Redirect target after a POST — back to the same filtered/paged view."""
    nxt = request.POST.get('next', '')
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        return nxt
    return reverse('ioc_database')


def _database_page(request, manual_formset=None, status=200):
    query = (request.GET.get('q') or '').strip()[:255]
    status_filter = request.GET.get('status', 'all')
    source_filter = request.GET.get('source', 'all')
    category_filter = request.GET.get('category', 'all')
    rows, counts = build_ioc_database(query, status_filter, source_filter, category_filter)
    return render(request, 'incidents/ioc_database.html', {
        'manual_formset': manual_formset if manual_formset is not None else ManualIOCFormSet(),
        # Keep the entry section open when we are re-rendering its errors.
        'entry_open': manual_formset is not None,
        'query': query,
        'status_filter': status_filter,
        'source_filter': source_filter,
        'category_filter': category_filter,
        # Filtering spans every ticket category; manual entry/edit only offers the
        # five kinds the analyst can record (File Name is context, not a category).
        'category_choices': TICKET_CATEGORY_CHOICES,
        'manual_category_choices': INVENTORY_CATEGORY_CHOICES,
        'counts': counts,
        'database': Paginator(rows, 30).get_page(request.GET.get('page')),
        'current_path': request.get_full_path(),
    }, status=status)


@login_required
@require_GET
def ioc_database(request):
    _require_manager(request.user)
    return _database_page(request)


@login_required
@require_POST
def ioc_manual_add(request):
    """Save the IOC rows typed into the manual-entry section."""
    _require_manager(request.user)
    formset = ManualIOCFormSet(request.POST)
    if not formset.is_valid():
        return _database_page(request, formset, status=400)

    entries = [form.cleaned_data for form in formset if form.cleaned_data.get('value')]
    if not entries:
        messages.error(request, 'กรุณากรอกอย่างน้อยหนึ่ง IOC / Enter at least one IOC.')
        return redirect('ioc_database')

    results = create_manual_iocs(entries, request.user)
    created = sum(1 for _entry, outcome in results if outcome == 'created')
    restored = sum(1 for _entry, outcome in results if outcome == 'restored')
    duplicates = [entry['value'] for entry, outcome in results if outcome == 'duplicate']
    if created or restored:
        messages.success(request, f'บันทึกแล้ว / Saved: {created} added, {restored} restored.')
    if duplicates:
        messages.warning(
            request,
            'มีอยู่แล้วในฐานข้อมูล / Already in the database: ' + ', '.join(duplicates))
    return redirect('ioc_database')


@login_required
@require_POST
def ioc_manual_edit(request):
    """Edit one manual IOC in place."""
    _require_manager(request.user)
    try:
        pk = int(request.POST.get('pk', ''))
    except (TypeError, ValueError):
        raise Http404
    form = ManualIOCEditForm(request.POST)
    if not form.is_valid():
        messages.error(request, 'ข้อมูลไม่ถูกต้อง / Check the values and try again.')
        return redirect(_safe_next(request))
    try:
        update_manual_ioc(pk, form.cleaned_data['category'], form.cleaned_data['value'],
                          form.cleaned_data['file_name'], request.user)
    except ValidationError as exc:
        messages.error(request, '; '.join(exc.messages))
    else:
        messages.success(request, 'แก้ไขแล้ว / Updated.')
    return redirect(_safe_next(request))


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
def ioc_note_save(request):
    """Save the note for any indicator — ticket-sourced or manual."""
    _require_manager(request.user)
    try:
        set_note(request.POST.get('category', ''), request.POST.get('value', ''),
                 request.POST.get('note', ''), request.user)
    except ValidationError as exc:
        messages.error(request, '; '.join(exc.messages))
    return redirect(_safe_next(request))


@login_required
@require_POST
def analyst_ioc_remove(request):
    """Soft-remove a mistaken manual IOC."""
    _require_manager(request.user)
    try:
        pk = int(request.POST.get('pk', ''))
    except (TypeError, ValueError):
        raise Http404
    if remove_analyst_ioc(pk, request.user):
        messages.success(request, 'ลบรายการ IOC แล้ว / Removed the IOC.')
    return redirect(_safe_next(request))
