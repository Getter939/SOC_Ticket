from django.db import models
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
        (ROLE_SOC_STAFF,       'SOC Staff'),
        (ROLE_SOC_MANAGER,     'SOC Manager'),
        (ROLE_SYSTEM_ADMIN,    'System Admin'),
        (ROLE_SYSTEM_OWNER,    'System Owner'),
        (ROLE_EXECUTIVE,       'Executive'),
        (ROLE_FORENSIC,        'Forensic Analyst'),
        (ROLE_REDTEAM_MANAGER, 'Red Team Manager'),
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
    role         = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default=ROLE_SOC_STAFF, verbose_name="บทบาท",
    )
    tier         = models.CharField(
        max_length=5, choices=TIER_CHOICES, blank=True, default='', verbose_name="ระดับ (Tier)",
    )

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
        """Red Team Manager — receives VA_PT and INFRA_SEC response requests."""
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
    def is_tier1(self):
        """SOC staff at Tier 1 — opens tickets, classifies, reviews, verifies.

        Under the redesigned workflow ``tier`` carries permission weight: only a
        Tier 1 analyst may create tickets and drive the T1 side of the lifecycle.
        """
        return self.is_soc_staff and self.tier == self.TIER_T1

    @property
    def is_tier2(self):
        """SOC staff at Tier 2 — handles escalated tickets (return-to-T1 / close only)."""
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
