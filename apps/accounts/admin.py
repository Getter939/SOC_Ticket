from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.template.response import TemplateResponse
from django.utils import timezone

from axes.models import AccessAttempt
from axes.utils import reset as reset_axes_attempts

from .models import AccountLockoutAudit, PasswordChangeAudit, UserProfile, MFAAudit
from .password_audit import password_audit_context
from .passwords import send_password_reset_email


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    # UserProfile now has a second FK to User (acting_tier_granted_by), so the
    # inline must say which one binds it to the parent user.
    fk_name = 'user'
    can_delete = False
    # The acting-tier grant is a privilege escalation. SOC Managers are is_staff
    # and can reach this admin, so the grant fields must be read-only for anyone
    # but a superuser — otherwise a manager could grant it to themselves. The
    # superuser-gated changelist actions below are the intended write path.
    _ACTING_TIER_FIELDS = (
        'acting_tier_access', 'acting_tier_granted_by', 'acting_tier_granted_at',
    )

    def get_readonly_fields(self, request, obj=None):
        readonly = tuple(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            readonly += self._ACTING_TIER_FIELDS
        else:
            # Who/when are set by the actions, never typed by hand.
            readonly += ('acting_tier_granted_by', 'acting_tier_granted_at')
        return readonly


@admin.register(MFAAudit)
class MFAAuditAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'username', 'event', 'actor')
    list_filter = ('event', 'created_at')
    search_fields = ('username', 'actor__username')
    readonly_fields = ('user', 'username', 'actor', 'event', 'reason', 'created_at')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


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
            messages.error(request, f'ไม่สามารถส่งข้อมูลบัญชีให้ {user.username} ได้')
    messages.success(request, f'ส่งข้อมูลบัญชีให้ผู้ใช้ {success_count} คนแล้ว')


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
            messages.error(request, f'ไม่สามารถส่งลิงก์รีเซ็ตให้ {user.username} ได้')
    messages.success(request, f'ส่งลิงก์รีเซ็ตรหัสผ่านแล้ว {success_count} รายการ')


@admin.action(description='Grant temporary Tier 1/2 access (SOC Managers)')
def grant_acting_tier(modeladmin, request, queryset):
    """Temporarily elevate selected SOC Managers to Tier 1 + Tier 2 work."""
    if not request.user.is_superuser:
        messages.error(request, 'เฉพาะ superuser เท่านั้นที่ให้สิทธิ์รักษาการ Tier ได้')
        return
    granted = skipped = 0
    now = timezone.now()
    for user in queryset.select_related('profile'):
        profile = getattr(user, 'profile', None)
        if profile is None or profile.role != UserProfile.ROLE_SOC_MANAGER:
            skipped += 1
            continue
        profile.acting_tier_access = True
        profile.acting_tier_granted_by = request.user
        profile.acting_tier_granted_at = now
        profile.save(update_fields=[
            'acting_tier_access', 'acting_tier_granted_by', 'acting_tier_granted_at',
        ])
        granted += 1
    if granted:
        messages.success(request, f'ให้สิทธิ์รักษาการ Tier แก่ผู้จัดการ SOC {granted} คนแล้ว')
    if skipped:
        messages.warning(
            request,
            f'Skipped {skipped} selected user(s) that are not SOC Managers.',
        )


@admin.action(description='Revoke temporary Tier 1/2 access')
def revoke_acting_tier(modeladmin, request, queryset):
    """Withdraw a previously granted acting-tier elevation."""
    if not request.user.is_superuser:
        messages.error(request, 'เฉพาะ superuser เท่านั้นที่เพิกถอนสิทธิ์รักษาการ Tier ได้')
        return
    revoked = 0
    for user in queryset.select_related('profile'):
        profile = getattr(user, 'profile', None)
        if profile is None or not profile.acting_tier_access:
            continue
        profile.acting_tier_access = False
        profile.acting_tier_granted_by = None
        profile.acting_tier_granted_at = None
        profile.save(update_fields=[
            'acting_tier_access', 'acting_tier_granted_by', 'acting_tier_granted_at',
        ])
        revoked += 1
    messages.success(request, f'เพิกถอนสิทธิ์รักษาการ Tier จากผู้ใช้ {revoked} คนแล้ว')


class UserAdmin(BaseUserAdmin):
    add_form = MyUserCreationForm
    inlines = (UserProfileInline,)
    actions = [
        send_welcome_email_action, send_password_reset_link,
        grant_acting_tier, revoke_acting_tier,
    ]
    list_display = (
        'username', 'email', 'first_name', 'last_name', 'role', 'tier',
        'acting_tier', 'is_staff',
    )
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

    @admin.display(description='Acting tier', boolean=True, ordering='profile__acting_tier_access')
    def acting_tier(self, obj):
        """Whether this SOC Manager currently holds a temporary tier grant."""
        try:
            return obj.profile.acting_tier_access
        except UserProfile.DoesNotExist:
            return False

    def get_actions(self, request):
        actions = super().get_actions(request)
        if not request.user.is_superuser:
            actions.pop('grant_acting_tier', None)
            actions.pop('revoke_acting_tier', None)
        return actions

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
                messages.success(request, f'ส่งลิงก์ตั้งรหัสผ่านครั้งแรกไปที่ {obj.email} แล้ว')
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


@admin.register(AccountLockoutAudit)
class AccountLockoutAuditAdmin(admin.ModelAdmin):
    """Expose manual lockout resets as a read-only security audit trail."""

    list_display = ('unlocked_at', 'username', 'ip_address', 'actor', 'attempts_cleared')
    list_filter = ('unlocked_at',)
    search_fields = ('username', 'ip_address', 'actor__username')
    list_select_related = ('user', 'actor')
    ordering = ('-unlocked_at',)
    readonly_fields = (
        'user', 'username', 'ip_address', 'actor', 'reason',
        'attempts_cleared', 'unlocked_at',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class AccessAttemptAdmin(admin.ModelAdmin):
    """Let a superuser clear one selected Axes username/IP lockout at a time."""

    list_display = ('username', 'ip_address', 'failures_since_start', 'attempt_time')
    list_filter = ('attempt_time',)
    search_fields = ('username', 'ip_address')
    ordering = ('-attempt_time',)
    actions = ('unlock_selected_lockouts',)

    @admin.action(description='Unlock selected username/IP lockouts')
    def unlock_selected_lockouts(self, request, queryset):
        if not request.user.is_superuser:
            self.message_user(
                request,
                'Only superusers may manually unlock accounts.',
                level=messages.ERROR,
            )
            return None

        attempts = list(queryset)
        if not attempts:
            self.message_user(request, 'Select at least one lockout to unlock.', level=messages.WARNING)
            return None

        if request.POST.get('confirm_unlock') != 'yes':
            return self._confirmation_response(request, attempts)

        reason = request.POST.get('reason', '').strip()
        if not reason:
            return self._confirmation_response(
                request,
                attempts,
                error='A reason is required before an account can be unlocked.',
            )

        unlocked_pairs = set()
        total_attempts_cleared = 0
        skipped = 0
        for attempt in attempts:
            username = (attempt.username or '').strip()
            ip_address = attempt.ip_address
            if not username or not ip_address:
                skipped += 1
                continue

            pair = (username, ip_address)
            if pair in unlocked_pairs:
                continue

            cleared = reset_axes_attempts(username=username, ip=ip_address)
            AccountLockoutAudit.objects.create(
                user=User.objects.filter(username=username).first(),
                username=username,
                ip_address=ip_address,
                actor=request.user,
                reason=reason,
                attempts_cleared=cleared,
            )
            unlocked_pairs.add(pair)
            total_attempts_cleared += cleared

        if unlocked_pairs:
            self.message_user(
                request,
                f'Unlocked {len(unlocked_pairs)} username/IP lockout pair(s) and cleared '
                f'{total_attempts_cleared} Axes attempt record(s).',
                level=messages.SUCCESS,
            )
        if skipped:
            self.message_user(
                request,
                f'Skipped {skipped} selected record(s) without both a username and IP address.',
                level=messages.WARNING,
            )
        return None

    def _confirmation_response(self, request, attempts, error=None):
        context = {
            **self.admin_site.each_context(request),
            'title': 'Confirm account unlock',
            'attempts': attempts,
            'opts': self.model._meta,
            'action_checkbox_name': admin.helpers.ACTION_CHECKBOX_NAME,
            'error': error,
            'reason': request.POST.get('reason', ''),
        }
        return TemplateResponse(
            request,
            'admin/accounts/accessattempt/unlock_confirmation.html',
            context,
        )

    def get_actions(self, request):
        actions = super().get_actions(request)
        if not request.user.is_superuser:
            actions.pop('unlock_selected_lockouts', None)
        return actions

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.unregister(User)
admin.site.register(User, UserAdmin)

# django-axes registers this model with the default admin site.  Replace that
# generic registration with a confirmation-and-audit workflow, but retain the
# same staff/model permissions for viewing attempts.
try:
    admin.site.unregister(AccessAttempt)
except admin.sites.NotRegistered:
    pass
admin.site.register(AccessAttempt, AccessAttemptAdmin)
