from django.db import models
from django.db.models import Q
from django.core.exceptions import ValidationError
from .mfa_models import AuthenticatorDevice, MFAAudit, MFARecoveryCode  # noqa: F401
from django.contrib.auth.models import User


class UserProfile(models.Model):
    ROLE_SOC_STAFF       = 'SOC_STAFF'
    ROLE_SOC_MANAGER     = 'SOC_MANAGER'
    ROLE_SYSTEM_ADMIN    = 'SYSTEM_ADMIN'
    ROLE_SYSTEM_OWNER    = 'SYSTEM_OWNER'
    ROLE_EXECUTIVE       = 'EXECUTIVE'
    # Response-team roles — receive specialised subtasks spawned by the SOC
    # Manager. They are NOT SOC members (is_soc is False): each works only the
    # tickets that carry a response request assigned to them.
    ROLE_FORENSIC        = 'FORENSIC'
    ROLE_REDTEAM_MANAGER = 'REDTEAM_MANAGER'

    ROLE_CHOICES = [
        (ROLE_SOC_STAFF,       'เจ้าหน้าที่ SOC'),
        (ROLE_SOC_MANAGER,     'ผู้จัดการ SOC'),
        (ROLE_SYSTEM_ADMIN,    'ผู้ดูแลระบบ'),
        (ROLE_SYSTEM_OWNER,    'เจ้าของระบบ'),
        (ROLE_EXECUTIVE,       'ผู้บริหาร'),
        (ROLE_FORENSIC,        'นักวิเคราะห์นิติวิทยาศาสตร์ดิจิทัล'),
        (ROLE_REDTEAM_MANAGER, 'ผู้จัดการ Red Team'),
    ]

    REDTEAM_VA = 'VA'
    REDTEAM_PENTEST = 'PENTEST'
    REDTEAM_HARDENING = 'HARDENING'
    REDTEAM_FUNCTION_CHOICES = [
        (REDTEAM_VA, 'Vulnerability Assessment (VA)'),
        (REDTEAM_PENTEST, 'Penetration Test'),
        (REDTEAM_HARDENING, 'Hardening'),
    ]

    TIER_T1 = 'T1'
    TIER_T2 = 'T2'
    TIER_CHOICES = [
        (TIER_T1, 'T1'),
        (TIER_T2, 'T2'),
    ]

    user         = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    department   = models.CharField(max_length=100, verbose_name="สังกัด/แผนก")
    phone        = models.CharField(max_length=15, verbose_name="เบอร์โทรศัพท์")
    request_date = models.DateField(auto_now_add=True, verbose_name="วันที่ขอเข้าใช้งาน")
    note         = models.TextField(blank=True, null=True, verbose_name="บันทึกเพิ่มเติม")
    # NO default. is_soc is true for ROLE_SOC_STAFF, and visible_to() grants
    # is_soc every ticket in the system — so defaulting to SOC_STAFF meant an
    # admin who saved this inline without consciously picking a role handed out
    # org-wide incident access. With no default the field falls back to '',
    # which matches no is_* property, so visible_to() returns none(): an
    # unconfigured profile sees nothing rather than everything. The admin form
    # renders an empty required <select>, forcing an explicit choice.
    role         = models.CharField(
        max_length=20, choices=ROLE_CHOICES, verbose_name="บทบาท",
    )
    redteam_function = models.CharField(
        max_length=20, choices=REDTEAM_FUNCTION_CHOICES, blank=True, default='',
        verbose_name='งาน Red Team ที่รับผิดชอบ',
        help_text='กำหนดให้บัญชีผู้จัดการ Red Team หนึ่งคนต่อหนึ่งประเภทงาน',
    )
    tier         = models.CharField(
        max_length=5, choices=TIER_CHOICES, blank=True, default='', verbose_name="ระดับ (Tier)",
    )
    # A superadmin may temporarily grant a SOC Manager the full Tier 1 + Tier 2
    # function set (ticket creation, triage intake, driving their own cases,
    # tier-2 actions) and revoke it again. The grant is set BY the superadmin —
    # a manager can never toggle their own — so it lives here as persisted state
    # rather than a session flag. Because every tier gate funnels through the
    # is_tier1/is_tier2 properties below, honouring this flag there lights up all
    # the scattered gates at once. Defaults off, so managers behave exactly as
    # before until a superadmin acts.
    acting_tier_access     = models.BooleanField(
        default=False, verbose_name="สิทธิ์ทำงานระดับ Tier ชั่วคราว",
    )
    acting_tier_granted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='acting_tier_grants', verbose_name="ผู้ให้สิทธิ์",
    )
    acting_tier_granted_at = models.DateTimeField(
        null=True, blank=True, verbose_name="ให้สิทธิ์เมื่อ",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['redteam_function'],
                condition=Q(role='REDTEAM_MANAGER') & ~Q(redteam_function=''),
                name='unique_redteam_manager_per_function',
            ),
        ]

    def clean(self):
        super().clean()
        if self.redteam_function and not self.is_redteam_manager:
            raise ValidationError({
                'redteam_function': 'กำหนดประเภทงานได้เฉพาะผู้จัดการ Red Team',
            })

    @property
    def is_soc_staff(self):
        return self.role == self.ROLE_SOC_STAFF

    @property
    def is_soc_manager(self):
        return self.role == self.ROLE_SOC_MANAGER

    @property
    def is_system_admin(self):
        return self.role == self.ROLE_SYSTEM_ADMIN

    @property
    def is_system_owner(self):
        return self.role == self.ROLE_SYSTEM_OWNER

    @property
    def is_executive(self):
        return self.role == self.ROLE_EXECUTIVE

    @property
    def is_forensic(self):
        """Forensic Analyst — receives FORENSIC_RCA response requests."""
        return self.role == self.ROLE_FORENSIC

    @property
    def is_redteam_manager(self):
        """Red Team Manager, assigned to one response function."""
        return self.role == self.ROLE_REDTEAM_MANAGER

    @property
    def is_response_team(self):
        """True for either response-team role (Forensic / Red Team Manager)."""
        return self.role in (self.ROLE_FORENSIC, self.ROLE_REDTEAM_MANAGER)

    @property
    def is_soc(self):
        """True for both SOC staff and SOC managers."""
        return self.role in (self.ROLE_SOC_STAFF, self.ROLE_SOC_MANAGER)

    @property
    def is_acting_tier_manager(self):
        """A SOC Manager the superadmin has temporarily elevated to tier work."""
        return self.is_soc_manager and self.acting_tier_access

    @property
    def is_tier1(self):
        """SOC staff at Tier 1 — opens tickets, classifies, reviews, verifies.

        Under the redesigned workflow ``tier`` carries permission weight: only a
        Tier 1 analyst may create tickets and drive the T1 side of the lifecycle.
        A SOC Manager granted temporary tier access counts here too.
        """
        if self.is_acting_tier_manager:
            return True
        return self.is_soc_staff and self.tier == self.TIER_T1

    @property
    def is_tier2(self):
        """SOC staff at Tier 2 — handles escalated tickets (return-to-T1 / close only).

        A SOC Manager granted temporary tier access counts here too.
        """
        if self.is_acting_tier_manager:
            return True
        return self.is_soc_staff and self.tier == self.TIER_T2

    def __str__(self):
        return f"Profile of {self.user.username}"


class PasswordResetRateLimit(models.Model):
    """A short-lived rate-limit counter with no recoverable personal data."""

    KEY_EMAIL = 'email'
    KEY_IP = 'ip'
    KEY_TYPES = [(KEY_EMAIL, 'Email'), (KEY_IP, 'IP address')]

    key_type = models.CharField(max_length=5, choices=KEY_TYPES)
    key_hash = models.CharField(max_length=64)
    window_started_at = models.DateTimeField()
    request_count = models.PositiveSmallIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=('key_type', 'key_hash'),
                name='accounts_password_reset_rate_limit_key',
            ),
        ]


class PasswordChangeAudit(models.Model):
    """Immutable audit metadata for password updates; passwords are never stored."""

    SOURCE_SELF_SERVICE_CHANGE = 'SELF_SERVICE_CHANGE'
    SOURCE_SELF_SERVICE_RESET = 'SELF_SERVICE_RESET'
    SOURCE_ADMIN = 'ADMIN'
    SOURCE_SYSTEM = 'SYSTEM'
    SOURCE_CHOICES = [
        (SOURCE_SELF_SERVICE_CHANGE, 'Self-service change'),
        (SOURCE_SELF_SERVICE_RESET, 'Password-reset link'),
        (SOURCE_ADMIN, 'Django admin'),
        (SOURCE_SYSTEM, 'System / management command'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='password_change_audits',
    )
    actor = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='password_change_actions',
    )
    source = models.CharField(max_length=24, choices=SOURCE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)
        indexes = [models.Index(fields=('user', 'created_at'))]

    def __str__(self):
        return f'Password change for {self.user.username} at {self.created_at:%Y-%m-%d %H:%M:%S}'


class AccountLockoutAudit(models.Model):
    """Immutable record of a privileged manual lockout reset.

    The username and IP address are retained even if the corresponding Django
    user is later renamed or deleted.  They identify the exact Axes lockout
    pair that was cleared; no password or login request data is stored here.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='account_lockout_resets',
    )
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    actor = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='account_lockout_reset_actions',
    )
    reason = models.TextField()
    attempts_cleared = models.PositiveIntegerField()
    unlocked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-unlocked_at',)
        indexes = [
            models.Index(fields=('username', 'unlocked_at')),
            models.Index(fields=('ip_address', 'unlocked_at')),
        ]

    def __str__(self):
        return (
            f'Lockout reset for {self.username} ({self.ip_address}) '
            f'at {self.unlocked_at:%Y-%m-%d %H:%M:%S}'
        )
