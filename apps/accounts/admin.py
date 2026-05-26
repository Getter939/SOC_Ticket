import secrets
import string

from django import forms
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings

from .models import UserProfile


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False


class MyUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text="ใส่อีเมลเพื่อใช้ส่งรหัสผ่านให้ผู้ใช้งาน")
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name")


@admin.action(description='ส่ง Email แจ้ง Username ให้ผู้ใช้งานที่เลือก')
def send_welcome_email_action(modeladmin, request, queryset):
    success_count = 0
    for user in queryset:
        if user.email:
            subject = 'ข้อมูลบัญชีผู้ใช้งานระบบ SOC Support'
            message = (
                f"สวัสดีคุณ {user.first_name},\n\n"
                f"Username: {user.username}\n\n"
                f"เข้าใช้งานได้ที่: {request.build_absolute_uri('/login/')}\n\n"
                f"หากลืมรหัสผ่าน กรุณาติดต่อ Admin เพื่อขอรีเซ็ตรหัสผ่านใหม่"
            )
            try:
                send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])
                success_count += 1
            except Exception as e:
                messages.error(request, f"Error sending to {user.email}: {e}")
    messages.success(request, f"ส่งข้อมูล Username ให้ผู้ใช้ {success_count} รายสำเร็จแล้ว")


@admin.action(description='รีเซ็ตรหัสผ่านและส่งเมลแจ้ง User')
def reset_and_send_password(modeladmin, request, queryset):
    for user in queryset:
        if user.email:
            new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
            user.set_password(new_password)
            user.save()
            subject = 'รหัสผ่านใหม่สำหรับระบบ SOC Support'
            message = (
                f"สวัสดีคุณ {user.first_name}\n\n"
                f"Username: {user.username}\n"
                f"Password ใหม่: {new_password}\n\n"
                f"กรุณาเปลี่ยนรหัสผ่านหลังจากเข้าสู่ระบบ"
            )
            send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])
    messages.success(request, "รีเซ็ตรหัสผ่านและส่งเมลเรียบร้อยแล้ว")


class UserAdmin(BaseUserAdmin):
    add_form = MyUserCreationForm
    inlines = (UserProfileInline,)
    actions = [send_welcome_email_action, reset_and_send_password]
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff')
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'password1', 'password2'),
        }),
    )

    def save_model(self, request, obj, form, change):
        is_new_user = not change and obj.pk is None
        raw_password = form.cleaned_data.get('password1')
        super().save_model(request, obj, form, change)

        if is_new_user and obj.email and raw_password:
            login_url = request.build_absolute_uri('/login/')
            subject = 'ยืนยันการเข้าใช้งานระบบ SOC Support'
            message = (
                f"สวัสดีคุณ {obj.first_name},\n\n"
                f"Username: {obj.username}\n"
                f"Password: {raw_password}\n\n"
                f"เข้าใช้งานได้ที่: {login_url}\n\n"
                f"กรุณาเปลี่ยนรหัสผ่านทันทีหลังการเข้าใช้งานครั้งแรก"
            )
            try:
                send_mail(subject, message, settings.EMAIL_HOST_USER, [obj.email])
                messages.success(request, f"ส่งข้อมูลการเข้าใช้งานไปที่ {obj.email} เรียบร้อยแล้ว")
            except Exception as e:
                messages.error(request, f"บันทึกสำเร็จแต่ส่งเมลล้มเหลว: {e}")


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
