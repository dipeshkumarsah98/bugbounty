from decimal import Decimal
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotFound
from django.conf import settings
from django.utils import timezone
from django.db.models import Count, Sum
from rest_framework.response import Response
from rest_framework import generics, viewsets, status
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from django.db import DatabaseError, transaction
from .permission import IsClient, IsHunter
from .models import Bounty, Bug, Skill, Comment, RewardTransaction
from .serializers import (BugDetailSerializer, CustomTokenObtainPairSerializer,
                          BountySerializer, 
                          BountyDetailSerializer,
                          BugSerializer, RewardSummarySerializer, RewardTransactionSerializer,
                          UserRegistrationSerializer,
                          OTPVerificationSerializer,
                          SkillSerializer,
                          CommentSerializer,
                          BugStatusSerializer,
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
            # TODO: Should load 5000 balance to the client account after verification
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
    queryset = Bounty.objects.select_related('created_by').annotate(bugs_count=Count('bugs')).order_by('-created_at').all()
    permission_classes = [IsAuthenticatedOrReadOnly, IsClient]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return BountyDetailSerializer
        return BountySerializer
    
class BugViewSet(viewsets.ModelViewSet):
    queryset = Bug.objects.select_related('related_bounty', 'submitted_by') \
                          .annotate(comments_count=Count('comments')) \
                          .order_by('-submitted_at').all()
    permission_classes = [IsAuthenticatedOrReadOnly, IsHunter] 

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

class BugStatusView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated, IsClient]
    serializer_class = BugStatusSerializer

    def post(self, request, *args, **kwargs):
        bug_id = self.kwargs.get('bugid')
        try:
            bug = Bug.objects.get(pk=bug_id)
        except Bug.DoesNotExist:
            raise NotFound(detail="Bug not found")
        
        if bug.status == 'pending':
            try:
                bounty = Bounty.objects.get(pk=bug.related_bounty_id)
            except Bounty.DoesNotExist:
                raise NotFound(detail="Bounty not found")

            if bounty.created_by != request.user:
                return Response({'detail': 'You do not have permission to change the status of this bug'}, status=status.HTTP_403_FORBIDDEN)
            
            new_status = request.data.get('status')

            if new_status not in ['Accepted', 'Rejected', 'Pending']:
                return Response({'detail': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)

            if new_status.lower() == 'accepted':
                if bug.is_accepted:
                    return Response({'detail': 'Bug already accepted'}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    with transaction.atomic():
                        bug.is_accepted = True
                        bug.status = new_status.lower()
                        bug.save()
                        #  Reward the hunter

                        # TODO: Balance should be reduced from the client account
                        reward_transaction = RewardTransaction.objects.create(
                            user=bug.submitted_by,
                            amount=bounty.rewarded_amount,
                            transaction_type='credit',
                            created_by=request.user,
                        )
                        reward_transaction.save()
                        # TODO: Send email to the hunter
                        # TODO: send_reward_email(bug.submitted_by.email, bounty.rewarded_amount)
                        # transaction.on_commit(lambda: send_reward_email(bug.submitted_by.email, bounty.rewarded_amount))

                except DatabaseError:
                    bug.is_accepted = False
                    bug.status = 'pending'
                    bug.save()

                    return Response({'detail': 'Error occurred while updating bug status'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                return Response({'detail': 'Bug status updated successfully'}, status=status.HTTP_200_OK)
            
            if new_status.lower() == 'rejected':
                if bug.status == 'rejected':
                    return Response({'detail': 'Bug already rejected'}, status=status.HTTP_400_BAD_REQUEST)
                
                if bug.is_accepted:
                    return Response({'detail': 'Cannot reject bug when it is once accepted'}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    with transaction.atomic():
                        bug.is_accepted = False
                        bug.status = new_status.lower()
                        bug.save()

                    #  send email to the hunter that the bug is rejected
                    # send_rejection_email(bug.submitted_by.email, bugId)
                except DatabaseError:
                    return Response({'detail': 'Error occurred while updating bug status'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                return Response({'detail': 'Bug status updated successfully'}, status=status.HTTP_200_OK)
            
            bug.status = new_status.lower()
            bug.save()

            return Response({'detail': 'Bug status updated successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Cannot change status of a bug that is already accepted or rejected'}, status=status.HTTP_400_BAD_REQUEST)

class RewardTransactionViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return RewardTransaction.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        return RewardTransactionSerializer

    @action(detail=False, methods=['get'])
    def summary(self, request):
        user = request.user
        # calculate total credits and total debits
        credits = RewardTransaction.objects.filter(user=user, transaction_type='credit') \
                                            .aggregate(total=Sum('amount'))['total'] or Decimal('0')

        debits = RewardTransaction.objects.filter(user=user, transaction_type='debit') \
                                            .aggregate(total=Sum('amount'))['total'] or Decimal('0')

        total_rewards = credits
        current_reward = credits - debits
        
        trans = RewardTransaction.objects.filter(user=user).order_by('-created_at')
        print("trans: {trans}")
        serializer = RewardSummarySerializer({
            'current_reward': current_reward,
            'total_reward': total_rewards,
            'transactions': trans
        })

        return Response(serializer.data)