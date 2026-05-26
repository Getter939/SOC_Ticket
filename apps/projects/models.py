from django.db import models
from django.contrib.auth.models import User
from apps.customers.models import Customer
from apps.incidents.models import Ticket


class Project(models.Model):
    STATUS_CHOICES = [
        ('Planning', 'วางแผน (Planning)'),
        ('Active', 'กำลังดำเนินการ (Active)'),
        ('On Hold', 'รอดำเนินการ (On Hold)'),
        ('Completed', 'เสร็จสิ้น (Completed)'),
    ]

    name = models.CharField(max_length=255, verbose_name="ชื่อโปรเจกต์")
    customer = models.ForeignKey(
        Customer, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='projects', verbose_name="ลูกค้า"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Planning', verbose_name="สถานะ")
    description = models.TextField(blank=True, null=True, verbose_name="รายละเอียด")
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='projects_created', verbose_name="ผู้สร้าง"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    @property
    def task_count(self):
        return self.tasks.count()

    @property
    def completed_task_count(self):
        return self.tasks.filter(status='Done').count()


class Task(models.Model):
    STATUS_CHOICES = [
        ('Todo', 'รอทำ (Todo)'),
        ('Doing', 'กำลังทำ (Doing)'),
        ('Done', 'เสร็จแล้ว (Done)'),
    ]

    PRIORITY_CHOICES = [
        ('Low', 'ต่ำ (Low)'),
        ('Medium', 'ปานกลาง (Medium)'),
        ('High', 'สูง (High)'),
        ('Critical', 'วิกฤต (Critical)'),
    ]

    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name='tasks', verbose_name="โปรเจกต์"
    )
    ticket = models.ForeignKey(
        Ticket, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='tasks', verbose_name="Ticket ที่เกี่ยวข้อง"
    )
    title = models.CharField(max_length=255, verbose_name="หัวข้องาน")
    description = models.TextField(blank=True, null=True, verbose_name="รายละเอียด")
    assignee = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='tasks_assigned', verbose_name="ผู้รับผิดชอบ"
    )
    due_date = models.DateField(null=True, blank=True, verbose_name="กำหนดส่ง")
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='Medium', verbose_name="ความสำคัญ")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Todo', verbose_name="สถานะ")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-priority', 'due_date']

    def __str__(self):
        return f"{self.title} ({self.project.name})"
