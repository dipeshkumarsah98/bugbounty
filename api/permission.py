from rest_framework.permissions import BasePermission

class IsClient(BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            return True

        return request.user.is_authenticated and request.user.role == 'client'

class IsHunter(BasePermission):
    def has_permission(self, request, view):
        print("action:: ", request.method)
        if request.method == 'GET':
            return True
        return request.user.is_authenticated and request.user.role == 'hunter'
