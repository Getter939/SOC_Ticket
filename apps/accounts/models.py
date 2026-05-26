from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    # --- Role choices ---
    # We use an explicit role field rather than Django's Groups/permissions
    # framework for legibility in a small team. Do not substitute Groups.
    ROLE_SOC_STAFF    = 'SOC_STAFF'
    ROLE_SOC_MANAGER  = 'SOC_MANAGER'
    ROLE_SYSTEM_ADMIN = 'SYSTEM_ADMIN'

    ROLE_CHOICES = [
        (ROLE_SOC_STAFF,    'SOC Staff'),
        (ROLE_SOC_MANAGER,  'SOC Manager'),
        (ROLE_SYSTEM_ADMIN, 'System Admin'),
    ]

    # --- Tier choices ---
    # Tier is a RECORDED SENIORITY LABEL ONLY.
    # It MUST NOT affect any permission or access-control logic anywhere.
    TIER_T1 = 'T1'
    TIER_T2 = 'T2'

    TIER_CHOICES = [
        (TIER_T1, 'T1'),
        (TIER_T2, 'T2'),
    ]

    # --- Fields ---
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    department = models.CharField(max_length=100, verbose_name="สังกัด/แผนก")
    phone = models.CharField(max_length=15, verbose_name="เบอร์โทรศัพท์")
    request_date = models.DateField(auto_now_add=True, verbose_name="วันที่ขอเข้าใช้งาน")
    note = models.TextField(blank=True, null=True, verbose_name="บันทึกเพิ่มเติม")
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default=ROLE_SOC_STAFF,
        verbose_name="บทบาท",
    )
    # tier is a seniority label for SOC staff only — blank for managers/admins.
    # It carries no permission weight: do not use it in any access check.
    tier = models.CharField(
        max_length=5,
        choices=TIER_CHOICES,
        blank=True,
        default='',
        verbose_name="ระดับ (Tier)",
    )

    # --- Role convenience properties ---
    # These are simple property methods — no DB queries, no logic beyond a
    # string comparison.  Call them on a profile instance you already hold.
    #
    # SAFETY NOTE: a User may have no UserProfile (e.g. a freshly created
    # superuser before a profile is assigned).  Callers must guard with:
    #     profile = getattr(user, 'profile', None)
    # and treat None as "no access" / safest default.  These properties
    # themselves never need to handle the None case because they are only
    # reachable on a profile instance.

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
    def is_soc(self):
        """True for both SOC staff and SOC managers."""
        return self.role in (self.ROLE_SOC_STAFF, self.ROLE_SOC_MANAGER)

    def __str__(self):
        return f"Profile of {self.user.username}"
