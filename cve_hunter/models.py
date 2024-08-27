from django.db import models

# Create your models here.
class CVE(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    published_date = models.DateField()
    severity = models.CharField(max_length=10, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ])

    def __str__(self):
        return self.cve_id

class Vendor(models.Model):
    name = models.CharField(max_length=255, unique=True)
    cves = models.ManyToManyField(CVE, related_name='vendors')

    def __str__(self):
        return self.name

class Product(models.Model):
    name = models.CharField(max_length=255)
    vendor = models.ForeignKey(Vendor, related_name='products', on_delete=models.CASCADE)
    cves = models.ManyToManyField(CVE, related_name='products')

    def __str__(self):
        return f'{self.vendor.name} - {self.name}'