from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.mail import send_mail

from .models import UserProfile
from .passwords import send_password_reset_email


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False


class MyUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text='Required for secure password setup.')
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')


@admin.action(description='Send username details to selected users')
def send_welcome_email_action(modeladmin, request, queryset):
    success_count = 0
    for user in queryset:
        if not user.email:
            continue
        subject = 'SOC Support System account details'
        message = (
            f'Hello {user.first_name},\n\n'
            f'Username: {user.username}\n\n'
            f'Sign in at: {request.build_absolute_uri("/login/")}\n\n'
            'Use the secure password-reset link on the sign-in page if needed.'
        )
        try:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL or None, [user.email])
            success_count += 1
        except Exception:
            messages.error(request, f'Unable to send account details for {user.username}.')
    messages.success(request, f'Sent account details to {success_count} user(s).')


@admin.action(description='Send secure password-reset links to selected users')
def send_password_reset_link(modeladmin, request, queryset):
    success_count = 0
    for user in queryset:
        if not (user.email and user.is_active and user.has_usable_password()):
            continue
        try:
            send_password_reset_email(user=user, request=request)
            success_count += 1
        except Exception:
            messages.error(request, f'Unable to send a reset link for {user.username}.')
    messages.success(request, f'Sent {success_count} secure password-reset link(s).')


class UserAdmin(BaseUserAdmin):
    add_form = MyUserCreationForm
    inlines = (UserProfileInline,)
    actions = [send_welcome_email_action, send_password_reset_link]
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'password1', 'password2'),
        }),
    )

    def save_model(self, request, obj, form, change):
        is_new_user = not change and obj.pk is None
        super().save_model(request, obj, form, change)

        if is_new_user and obj.email:
            try:
                send_password_reset_email(user=obj, request=request)
                messages.success(request, f'Sent a secure first-password link to {obj.email}.')
            except Exception:
                messages.error(
                    request,
                    'User saved, but the first-password link could not be sent.',
                )


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
