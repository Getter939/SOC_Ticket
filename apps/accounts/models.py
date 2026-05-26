from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    department = models.CharField(max_length=100, verbose_name="สังกัด/แผนก")
    phone = models.CharField(max_length=15, verbose_name="เบอร์โทรศัพท์")
    request_date = models.DateField(auto_now_add=True, verbose_name="วันที่ขอเข้าใช้งาน")
    note = models.TextField(blank=True, null=True, verbose_name="บันทึกเพิ่มเติม")

    def __str__(self):
        return f"Profile of {self.user.username}"
