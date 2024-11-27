from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import generics, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from .permission import IsClient, IsHunter
from .models import Bounty, Bug, Skill
from .serializers import (CustomTokenObtainPairSerializer,
                          BountySerializer, 
                          BugSerializer, 
                          UserRegistrationSerializer,
                          OTPVerificationSerializer,
                          SkillSerializer
                          )

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
        
        # Get tokens from validated data
        data = serializer.validated_data

        access_token = data.pop('access', None)
        refresh_token = data.pop('refresh', None)
        
        # Create a response with any additional data (e.g., user role)
        response = Response(data)
        
        # Set cookies
        access_token_expiry = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
        refresh_token_expiry = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
        
        response.set_cookie(
            key='access_token',
            value=access_token,
            expires=timezone.now() + access_token_expiry,
            httponly=True,
            secure=not settings.DEBUG,
            samesite='Strict',
        )
        
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            expires=timezone.now() + refresh_token_expiry,
            httponly=True,
            secure=not settings.DEBUG,
            samesite='Strict',
        )
        
        return response

class CustomTokenRefreshView(TokenRefreshView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            return Response({'detail': 'Refresh token not provided.'}, status=400)
        
        serializer = self.get_serializer(data={'refresh': refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        data = serializer.validated_data

        access_token = data.get('access')
        access_token_expiry = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
        
        response = Response({'detail': 'Token refreshed.'})

        response.set_cookie(
            key='access_token',
            value=access_token,
            expires=timezone.now() + access_token_expiry,
            httponly=True,
            secure=not settings.DEBUG,
            samesite='Strict',
        )

        return response

class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

class OTPVerificationView(generics.GenericAPIView):
    serializer_class = OTPVerificationSerializer
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Account verified successfully'}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            return Response({'detail': 'No refresh token provided.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            pass

        response = Response({'detail': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        response.delete_cookie(
            'access_token',
            path='/',
            domain=None,  
            samesite='Strict',
        )
        response.delete_cookie(
            'refresh_token',
            path='/',
            domain=None,
            samesite='Strict',
        )

        return response

class BountyViewSet(viewsets.ModelViewSet):
    queryset = Bounty.objects.all()
    serializer_class = BountySerializer 
    permission_classes = [IsAuthenticated, IsClient]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class BugViewSet(viewsets.ModelViewSet):
    queryset = Bug.objects.all()
    serializer_class = BugSerializer
    permission_classes = [IsAuthenticated, IsHunter]  # Only hunters can submit bugs

    def perform_create(self, serializer):
        serializer.save(submitted_by=self.request.user)

class SkillViewSet(viewsets.ModelViewSet):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [AllowAny]