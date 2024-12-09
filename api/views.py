from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotFound
from django.conf import settings
from django.utils import timezone
from django.db.models import Count
from rest_framework.response import Response
from rest_framework import generics, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from .permission import IsClient, IsHunter
from .models import Bounty, Bug, Skill, Comment
from .serializers import (BugDetailSerializer, CustomTokenObtainPairSerializer,
                          BountySerializer, 
                          BountyDetailSerializer,
                          BugSerializer, 
                          UserRegistrationSerializer,
                          OTPVerificationSerializer,
                          SkillSerializer,
                          CommentSerializer
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
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
        )
        
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            expires=timezone.now() + refresh_token_expiry,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
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
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
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
            samesite=settings.COOKIE_SAMESITE,
        )
        response.delete_cookie(
            'refresh_token',
            path='/',
            domain=None,
            samesite=settings.COOKIE_SAMESITE,
        )

        return response

class BountyViewSet(viewsets.ModelViewSet):
    queryset = Bounty.objects.select_related('created_by').annotate(bugs_count=Count('bugs')).all()
    permission_classes = [IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return BountyDetailSerializer
        return BountySerializer
    
class BugViewSet(viewsets.ModelViewSet):
    queryset = Bug.objects.select_related('related_bounty', 'submitted_by') \
                          .annotate(comments_count=Count('comments')) \
                          .all()
    permission_classes = [IsAuthenticatedOrReadOnly] 

    def get_serializer_context(self):
        return {'request': self.request}
    
    def perform_create(self, serializer):
        serializer.save(submitted_by=self.request.user)
    
    def get_serializer_class(self):
        if self.action == 'retrieve':
            return BugDetailSerializer
        return BugSerializer
   
class SkillViewSet(viewsets.ModelViewSet):
    queryset = Skill.objects.all()
    serializer_class = SkillSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

class BugCommentListCreateView(generics.ListCreateAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        bug_id = self.kwargs.get('bugid')
        if not Bug.objects.filter(pk=bug_id).exists():
            raise NotFound(detail="Bug not found")

        return Comment.objects.prefetch_related('user').filter(bug_id=bug_id).order_by('-created_at')
    
    def perform_create(self, serializer):
        bug_id = self.kwargs.get('bugid')
        try:
            bug = Bug.objects.get(pk=bug_id)
        except Bug.DoesNotExist:
            raise NotFound(detail="Bug not found")

        serializer.save(bug=bug, user=self.request.user)
