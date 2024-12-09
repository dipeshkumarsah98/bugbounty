from django.contrib import admin
from .models import Bounty, Bug, Skill, User, Comment

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

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('bug', 'user', 'created_at')
    search_fields = ('user__email', 'bug__title', 'text')
