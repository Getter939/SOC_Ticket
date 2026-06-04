from django.contrib import admin
from .models import Customer, CustomerEmail, CustomerPhone


class CustomerEmailInline(admin.TabularInline):
    model = CustomerEmail
    extra = 1


class CustomerPhoneInline(admin.TabularInline):
    model = CustomerPhone
    extra = 1


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at', 'updated_at')
    search_fields = ('name', 'note')
    inlines = [CustomerEmailInline, CustomerPhoneInline]
