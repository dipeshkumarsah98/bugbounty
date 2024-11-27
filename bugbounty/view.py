from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.reverse import reverse

class APIRootView(APIView):
    """
    API Root View
    """
    permission_classes = [AllowAny]
    def get(self, request, format=None):
        return Response({
            'skills': reverse('skill-list', request=request, format=format),
            'bounties': reverse('bounty-list', request=request, format=format),
            'bugs': reverse('bug-list', request=request, format=format),
            'auth': {
                'login': reverse('token_obtain_pair', request=request, format=format),
                'refresh': reverse('token_refresh', request=request, format=format),
                'register': reverse('user_registration', request=request, format=format),
                'logout': reverse('logout', request=request, format=format),
            },
        })
