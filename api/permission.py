from rest_framework.permissions import BasePermission
import logging

logger = logging.getLogger(__name__)
class IsClient(BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            return True
        logging.info(f"user {request.user.email} with role {request.user.role} is trying to access client role {request.method} method")
        return request.user.is_authenticated and request.user.role == 'client'

class IsHunter(BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            return True
        logging.info(f"user {request.user.email} with role {request.user.role} is trying to access hunter role {request.method} method")
        return request.user.is_authenticated and request.user.role == 'hunter'
