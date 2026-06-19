from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    ROLE_SOC_STAFF    = 'SOC_STAFF'
    ROLE_SOC_MANAGER  = 'SOC_MANAGER'
    ROLE_SYSTEM_ADMIN = 'SYSTEM_ADMIN'
    ROLE_SYSTEM_OWNER = 'SYSTEM_OWNER'

    ROLE_CHOICES = [
        (ROLE_SOC_STAFF,    'SOC Staff'),
        (ROLE_SOC_MANAGER,  'SOC Manager'),
        (ROLE_SYSTEM_ADMIN, 'System Admin'),
        (ROLE_SYSTEM_OWNER, 'System Owner'),
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
