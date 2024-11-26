from rest_framework.permissions import BasePermission

class IsClient(BasePermission):
    """
    Allows access only to users with role 'client'.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'client'

class IsHunter(BasePermission):
    """
    Allows access only to users with role 'hunter'.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'hunter'
