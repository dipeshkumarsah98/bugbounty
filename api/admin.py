from django.contrib import admin
from .models import Bounty, Bug, Skill, User

# Register your models here.
@admin.register(Bounty)
class BountyAdmin(admin.ModelAdmin):
    list_display = ['title', 'description', 'rewarded_amount', 'created_at', 'created_by']
    search_fields = ['title', 'description']
    list_filter = ['created_at']

@admin.register(Bug)
class BugAdmin(admin.ModelAdmin):
    list_display = ['title', 'description', 'guide']
    search_fields = ['title', 'description']
    list_filter = ['submitted_at']

@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    list_display = ['name']
    search_fields = ['name']