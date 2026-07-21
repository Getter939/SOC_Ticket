from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.mail import send_mail

from .models import PasswordChangeAudit, UserProfile
from .password_audit import password_audit_context
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
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'tier', 'is_staff')
    list_select_related = ('profile',)
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'password1', 'password2'),
        }),
    )

    @admin.display(description='Role', ordering='profile__role')
    def role(self, obj):
        """Show the profile's human-readable role in the user changelist."""
        try:
            return obj.profile.get_role_display()
        except UserProfile.DoesNotExist:
            return '—'

    @admin.display(description='Tier', ordering='profile__tier')
    def tier(self, obj):
        """Show the profile's human-readable tier in the user changelist."""
        try:
            return obj.profile.get_tier_display() or '—'
        except UserProfile.DoesNotExist:
            return '—'

    def save_model(self, request, obj, form, change):
        is_new_user = not change and obj.pk is None
        with password_audit_context(
            source=PasswordChangeAudit.SOURCE_ADMIN,
            actor=request.user,
        ):
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

    def user_change_password(self, request, id, form_url=''):
        with password_audit_context(
            source=PasswordChangeAudit.SOURCE_ADMIN,
            actor=request.user,
        ):
            return super().user_change_password(request, id, form_url)


@admin.register(PasswordChangeAudit)
class PasswordChangeAuditAdmin(admin.ModelAdmin):
    """Expose credential history without ever exposing credential material."""

    list_display = ('created_at', 'user', 'source', 'actor')
    list_filter = ('source', 'created_at')
    search_fields = ('user__username', 'actor__username')
    list_select_related = ('user', 'actor')
    ordering = ('-created_at',)
    readonly_fields = ('user', 'actor', 'source', 'created_at')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
