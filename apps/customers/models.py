from django.db import models


class Customer(models.Model):
    name = models.CharField(max_length=255, verbose_name="ชื่อลูกค้า")
    note = models.TextField(blank=True, null=True, verbose_name="บันทึกเพิ่มเติม")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class CustomerEmail(models.Model):
    customer = models.ForeignKey(Customer, related_name='emails', on_delete=models.CASCADE)
    email = models.EmailField(verbose_name="Email")

    def __str__(self):
        return self.email


class CustomerPhone(models.Model):
    customer = models.ForeignKey(Customer, related_name='phones', on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20, verbose_name="เบอร์โทร")

    def __str__(self):
        return self.phone_number
