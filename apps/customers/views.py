from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from .forms import CustomerForm, EmailFormSet, PhoneFormSet
from .models import Customer


def _has_soc_access(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_soc)


@login_required
def customer_list(request):
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเข้าถึงข้อมูลลูกค้าได้')
        return redirect('home')

    search_query = request.GET.get('search', '')
    if search_query:
        customers = Customer.objects.filter(
            Q(name__icontains=search_query) |
            Q(emails__email__icontains=search_query) |
            Q(phones__phone_number__icontains=search_query) |
            Q(note__icontains=search_query)
        ).distinct().order_by('-created_at')
    else:
        customers = Customer.objects.all().order_by('-created_at')
    return render(request, 'customers/customer_list.html', {'customers': customers})


@login_required
def add_customer(request):
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเพิ่มข้อมูลลูกค้าได้')
        return redirect('customer_list')

    if request.method == 'POST':
        form = CustomerForm(request.POST)
        emails = EmailFormSet(request.POST)
        phones = PhoneFormSet(request.POST)
        if form.is_valid() and emails.is_valid() and phones.is_valid():
            customer = form.save()
            emails.instance = customer
            emails.save()
            phones.instance = customer
            phones.save()
            return redirect('customer_list')
    else:
        form = CustomerForm()
        emails = EmailFormSet()
        phones = PhoneFormSet()

    return render(request, 'customers/add_customer.html', {
        'form': form, 'emails': emails, 'phones': phones
    })


@login_required
def edit_customer(request, pk):
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถแก้ไขข้อมูลลูกค้าได้')
        return redirect('customer_list')

    customer = get_object_or_404(Customer, pk=pk)
    if request.method == 'POST':
        form = CustomerForm(request.POST, instance=customer)
        emails = EmailFormSet(request.POST, instance=customer)
        phones = PhoneFormSet(request.POST, instance=customer)
        if form.is_valid() and emails.is_valid() and phones.is_valid():
            form.save()
            emails.save()
            phones.save()
            return redirect('customer_list')
    else:
        form = CustomerForm(instance=customer)
        emails = EmailFormSet(instance=customer)
        emails.extra = 0
        phones = PhoneFormSet(instance=customer)
        phones.extra = 0

    return render(request, 'customers/add_customer.html', {
        'form': form, 'emails': emails, 'phones': phones, 'edit_mode': True
    })


@login_required
def delete_customer(request, pk):
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถลบข้อมูลลูกค้าได้')
        return redirect('customer_list')

    customer = get_object_or_404(Customer, pk=pk)
    if request.method == 'POST':
        customer.delete()
        return redirect('customer_list')
    return render(request, 'customers/confirm_delete_customer.html', {'customer': customer})
