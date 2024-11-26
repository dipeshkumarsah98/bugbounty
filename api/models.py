from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin,AbstractUser
)
from django.conf import settings


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('hunter', 'Hunter'),
        ('client', 'Client'),
    ]
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    skills = models.ManyToManyField('Skill', blank=True)
    industry = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # Required for admin access
    is_active = models.BooleanField(default=False)  # User inactive until email verification
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    objects = UserManager()
    USERNAME_FIELD = 'email' 
    REQUIRED_FIELDS = ['role']  

    def __str__(self):
        return self.email

class Skill(models.Model):
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name

class Bounty(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    title = models.CharField(max_length=255)
    description = models.TextField()
    expiry_date = models.DateTimeField()
    attachments = models.FileField(upload_to='bounties/', blank=True, null=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    rewarded_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='bounties_created')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class Bug(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    guide = models.TextField(blank=True)
    attachment = models.FileField(upload_to='bugs/', blank=True, null=True)
    is_accepted = models.BooleanField(default=False)
    related_bounty = models.ForeignKey(Bounty, on_delete=models.CASCADE, related_name='bugs')
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='bugs_submitted')
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class RewardTransaction(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ('credit', 'Credit'),
        ('debit', 'Debit'),
    ]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reward_transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_type = models.CharField(max_length=6, choices=TRANSACTION_TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='transactions_created')

    def __str__(self):
        return f"{self.transaction_type.capitalize()} - {self.amount} to {self.user.username}"
