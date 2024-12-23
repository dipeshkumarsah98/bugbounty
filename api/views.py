from decimal import Decimal
from django.utils import timezone
import os
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotFound
from django.conf import settings
from django.db.models.functions import Coalesce
from django.db.models import Count, Sum, Q, DecimalField, F, Avg
from rest_framework.response import Response
from rest_framework import generics, viewsets, status
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
import logging
from django.db import DatabaseError, transaction
from django.shortcuts import get_object_or_404
from .permission import IsClient, IsHunter
from .models import Bounty, Bug, Skill, Comment, RewardTransaction
from .utils import get_user_balance, send_bug_rejected_email, send_reward_email, send_withdrawal_email
from .serializers import (BugDetailSerializer, CustomTokenObtainPairSerializer,
                          BountySerializer, 
                          BountyDetailSerializer,
                          BugSerializer, RewardSummarySerializer, RewardTransactionSerializer,
                          HunterProfileSerializer,
                          UserRegistrationSerializer,
                          OTPVerificationSerializer,
                          SkillSerializer,
                          CommentSerializer,
                          BugStatusSerializer,
                          LeaderboardUserSerializer,
                          DashboardSerializer
                          )
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

User = get_user_model()

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
    queryset = Bounty.objects.select_related('created_by').filter(expiry_date__gt=timezone.now()) \
        .annotate(bugs_count=Count('bugs')).order_by('-created_at').all()
    permission_classes = [IsAuthenticatedOrReadOnly, IsClient]

    logger.info(f"Bounty View set: access_key {os.environ.get('S3_ACCESS_KEY')}, secret_key {os.environ.get('S3_SECRET_KEY')}")

    def perform_create(self, serializer):
        logger.info(f"Creating new Bounty: access_key {os.environ.get('S3_ACCESS_KEY')}, secret_key {os.environ.get('S3_SECRET_KEY')}")
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
            logger.error(f"Bug {bug_id} not found")
            raise NotFound(detail="Bug not found")

        serializer.save(bug=bug, user=self.request.user)

class BugStatusView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated, IsClient]
    serializer_class = BugStatusSerializer

    def post(self, request, *args, **kwargs):
        user = request.user
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

            if bounty.created_by != user:
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
                        bug.approved_at = timezone.now()
                        bug.save()
                        #  Reward the hunter

                        # TODO: Balance should be reduced from the client account
                        reward_transaction = RewardTransaction.objects.create(
                            user=bug.submitted_by,
                            amount=bounty.rewarded_amount,
                            transaction_type='credit',
                            created_by=request.user,
                            note=f"Bug Bounty Reward - {bounty.severity} issue"
                        )
                        reward_transaction.save()

                except DatabaseError as e:
                    bug.is_accepted = False
                    bug.status = 'pending'
                    bug.save()

                    logging.error(f"Error occurred while updating bug status: {e}")

                    return Response({'detail': 'Error occurred while updating bug status'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                send_reward_email(bug.submitted_by.email, bug.submitted_by.name, bounty.rewarded_amount, bug.related_bounty.title)
                logger.info(f"User {user.email} accepted bug {bug.id} and rewarded {bounty.rewarded_amount} to hunter {bug.submitted_by.email}")

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
                        bug.approved_at = timezone.now()
                        bug.save()

                except DatabaseError as e:
                    logging.error(f"Error occurred while updating bug status: {e}")
                    return Response({'detail': 'Error occurred while updating bug status'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                send_bug_rejected_email(bug.submitted_by.email, bug.submitted_by.name, bug.related_bounty.title) 

                return Response({'detail': 'Bug status updated successfully'}, status=status.HTTP_200_OK)
            
            bug.status = new_status.lower()
            bug.save()
            logger.info(f"User {user.email} updated status of bug {bug.id} to {new_status}")
            return Response({'detail': 'Bug status updated successfully'}, status=status.HTTP_200_OK)
        else:
            logger.warning(f"User {user.email} Cannot change status of a bug, it's current status is {bug.status}")
            return Response({'detail': 'Cannot change status of a bug that is already accepted or rejected'}, status=status.HTTP_400_BAD_REQUEST)

class RewardTransactionViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return RewardTransaction.objects.filter(user=self.request.user).order_by('-created_at')

    def get_serializer_class(self):
        return RewardTransactionSerializer

    @action(detail=False, methods=['get'])
    def summary(self, request):
        user = request.user
        # calculate total credits and total debits
        data = get_user_balance(user)
        
        trans = RewardTransaction.objects.filter(user=user).order_by('-created_at')
        serializer = RewardSummarySerializer({
            'current_reward': data.get("balance"),
            'total_reward': data.get("total_credits"),
            'transactions': trans
        })

        return Response(serializer.data)
class WithdrawRewardViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    http_method_names = ['post']

    def create(self, request):
        amount_str = request.data.get('amount')
        if not amount_str:
            return Response({'detail': 'Amount is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = Decimal(amount_str)
        except (ValueError, TypeError):
            return Response({'detail': 'Invalid amount'}, status=status.HTTP_400_BAD_REQUEST)

        if amount <= 0:
            return Response({'detail': 'Amount must be greater than 0'}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        current_reward = get_user_balance(user).get('balance', Decimal('0'))

        if amount > current_reward:
            logger.info(f"User {user.email} requested withdrawal of {amount} but has only {current_reward} in balance")
            return Response({'detail': 'Insufficient balance'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                transaction_obj = RewardTransaction.objects.create(
                    user=user,
                    amount=amount,
                    transaction_type='debit',
                    created_by=user,
                    note='Withdrawal to Wallet'  
                )
        except DatabaseError as e:
            logging.error(f"Error occurred while processing withdrawal: {e}") 
            return Response({'detail': 'Error occurred while processing withdrawal'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Return updated balance or transaction details
        updated_balance = get_user_balance(user).get('balance', Decimal('0'))

        logger.info(f"User {user.email} requested withdrawal of {amount} and transaction id is {transaction_obj.id}")

        send_withdrawal_email(user.email, user.name, int(amount), transaction_obj.id)

        return Response({
            'detail': 'Withdrawal processed successfully',
            'new_balance': str(updated_balance),
            'transaction_id': transaction_obj.id
        }, status=status.HTTP_200_OK)

class LeaderboardView(generics.ListAPIView):
    serializer_class = LeaderboardUserSerializer
    permission_classes = [IsAuthenticated] 

    def get_queryset(self):
        credit = Coalesce(Sum('reward_transactions__amount', filter=Q(reward_transactions__transaction_type='credit')), 0, output_field=DecimalField())
        debits = Coalesce(Sum('reward_transactions__amount', filter=Q(reward_transactions__transaction_type='debit')), 0, output_field=DecimalField())
        solved_bugs = Count('bugs_submitted', distinct=True, filter=Q(bugs_submitted__is_accepted=True))

        return (
            User.objects
            .filter(role='hunter')
            .annotate(
                net_reward=credit - debits,
                solved_bugs=solved_bugs
            )
            .order_by('-solved_bugs', '-net_reward')[:10]
        )

class HunterProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        # Get the hunter user
        hunter = get_object_or_404(User, pk=id, role='hunter')

        # Calculate rank
        rank = self.get_rank(hunter)

        # Total bugs reported
        total_bugs_reported = Bug.objects.filter(submitted_by=hunter).count()

        # Success rate
        approved_bugs = Bug.objects.filter(submitted_by=hunter, is_accepted=True).count()
        success_rate = (approved_bugs / total_bugs_reported * 100) if total_bugs_reported > 0 else 0.0

        # Recent activities
        recent_activities = self.get_recent_activities(hunter)
        reward = get_user_balance(hunter);

        data = {
            'name': hunter.name,
            'email': hunter.email,
            'total_earned': reward.get('total_credits', Decimal('0')),
            'current_balance': reward.get('balance', Decimal('0')),
            'solved_bugs': approved_bugs,
            'rank': rank,
            'total_bugs_reported': total_bugs_reported,
            'success_rate': success_rate,
            'recent_activities': recent_activities
        }

        serializer = HunterProfileSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def get_rank(self, hunter):
        # Annotate all hunters with net reward
        credit = Coalesce(Sum('reward_transactions__amount', filter=Q(reward_transactions__transaction_type='credit')), Decimal('0'))
        debits = Coalesce(Sum('reward_transactions__amount', filter=Q(reward_transactions__transaction_type='debit')), Decimal('0'))
        solved_bugs = Count('bugs_submitted', filter=Q(bugs_submitted__is_accepted=True))

        all_hunters = (User.objects
                       .filter(role='hunter')
                       .annotate(net_reward=credit - debits, solved_bugs=solved_bugs)
                       .order_by('-solved_bugs', '-net_reward', 'id'))

        # Get a list of hunter ids in order
        hunter_ids = list(all_hunters.values_list('id', flat=True))
        # rank is the index of the hunter in this ordered list + 1
        rank = hunter_ids.index(hunter.id) + 1
        return rank

    def get_recent_activities(self, hunter):
        # Get recent bugs (submitted by hunter)
        # Fields: date=submitted_at, action="Submitted bug {title}", reward=None
        bug_activities = Bug.objects.filter(submitted_by=hunter).select_related('related_bounty').order_by('-submitted_at')[:5]
        bug_acts = [{
            'date': b.submitted_at,
            'action': f"Submitted bug '{b.related_bounty.title}'",
            'reward': None
        } for b in bug_activities]

        # Get recent reward transactions
        # Fields: date=created_at, action depends on transaction_type, reward=amount
        # TODO: We don't need transaction stuff (done)
        transaction_activities = RewardTransaction.objects.filter(user=hunter).order_by('-created_at')[:5]
        trans_acts = []
        for t in transaction_activities:
            if t.transaction_type == 'credit':
                act = "Received reward"
            else:
                act = "Withdrew reward"
            trans_acts.append({
                'date': t.created_at,
                'action': act,
                'reward': t.amount
            })

        # Combine and sort by date (descending)
        combined = bug_acts + trans_acts
        combined.sort(key=lambda x: x['date'], reverse=True)

        # Return top 5 combined recent activities
        return bug_acts[:5]

class DashboardView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user

        data = {
            "active_bounties": self.get_active_bounties(user),
            "my_token": str(self.get_user_balance(user)),
            "top_hunter_of_the_month": self.get_top_hunter_of_the_month(),
            "recent_activities": self.get_recent_activities(user),
            "performance_insight": self.get_performance_insight(user)
        }
        print(f"recent activities: {data['recent_activities']}")
        serializer = DashboardSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    def get_user_balance(self, user):
        # net_balance = sum(credits) - sum(debits)
        aggregate_data = RewardTransaction.objects.filter(user=user).aggregate(
            total_credits=Coalesce(Sum('amount', filter=Q(transaction_type='credit')), Decimal('0')),
            total_debits=Coalesce(Sum('amount', filter=Q(transaction_type='debit')), Decimal('0'))
        )

        return aggregate_data['total_credits'] - aggregate_data['total_debits']

    def get_active_bounties(self, user):
        now = timezone.now()
        if user.role == 'client':
            # Active bounties created by this client that are not expired
            return Bounty.objects.filter(created_by=user, expiry_date__gt=now).count()
        else:
            # For hunter: Consider active bounties as those not expired and possibly open to hunters
            return Bounty.objects.filter(expiry_date__gt=now).count()

    def get_top_hunter_of_the_month(self):
        # Simple approach: top hunter by net reward overall.
        # If you need by month, filter RewardTransaction by current month.
        # For demonstration, just top overall:
        credits = Coalesce(Sum('reward_transactions__amount', filter=Q(reward_transactions__transaction_type='credit')), Decimal('0'))
        debits = Coalesce(Sum('reward_transactions__amount', filter=Q(reward_transactions__transaction_type='debit')), Decimal('0'))

        top_hunter = (User.objects
                      .filter(role='hunter')
                      .annotate(net_reward=credits - debits)
                      .order_by('-net_reward')
                      .first())

        if top_hunter:
            return {
                "id": top_hunter.id,
                "hunter_name": top_hunter.name or top_hunter.email,
                "net_reward": str(top_hunter.net_reward)
            }
        return None

    def get_recent_activities(self, user):
        # For demonstration, limit to 3 items.
        activities = []
        if user.role == 'client':
            # Recent bounties created
            recent_bounties = Bounty.objects.filter(created_by=user).order_by('-created_at')[:2]
            for bounty in recent_bounties:
                activities.append({
                    'date': bounty.created_at,
                    'action':f"Created a new bounty: {bounty.title}"
                    })
            
            # TODO: Add date for each activity

            # Approved bugs:
            # Assuming approved bugs are those where is_accepted=True
            # and 'approved by client' means the client decided it. 
            # This might require a more complex logic depending on how approval is recorded.
            approved_bugs = Bug.objects.filter(related_bounty__created_by=user, is_accepted=True).order_by('-submitted_at')[:1]
            for bug in approved_bugs:
                activities.append({
                    "date": bug.approved_at if bug.approved_at else bug.submitted_at,
                    'action': f"Approved bug in bounty '{bug.related_bounty.title}'"
                    })
        else:
            # Hunter’s activities: recent bug submissions
            submitted_bugs = Bug.objects.filter(submitted_by=user).order_by('-submitted_at')[:3]
            for bug in submitted_bugs:
                activities.append({
                    'date': bug.submitted_at,
                    'action': f"Submitted bug in bounty '{bug.related_bounty.title}'"
                    })

        return activities

    def get_performance_insight(self, user):
        if user.role == 'client':
            return self.get_client_performance_insight(user)
        else:
            return self.get_hunter_performance_insight(user)

    def get_client_performance_insight(self, user):
        # total bug approved in his bounty
        approved_bugs = Bug.objects.filter(related_bounty__created_by=user, is_accepted=True)
        total_approved = approved_bugs.count()

        # Response time: average time from bug submission to acceptance
        # Assuming acceptance timestamp = submitted_at for demonstration, 
        # In real scenario, you'd need a field to track acceptance time.
        # Let's assume acceptance is indicated by is_accepted and acceptance time = submitted_at + some placeholder
        # If there's no separate acceptance time, you need to store when a bug was accepted.
        # For demonstration, assume bug accepted at submitted_at (not realistic):
        response_time = None
        if total_approved > 0:
            # If you had a field like bug.approved_at, you could do:
            response_time = str(approved_bugs.aggregate(avg_time=Avg(F('approved_at') - F('submitted_at')))['avg_time'])
            response_time = "N/A" if response_time == "None" else str(response_time)
            # Without that, we can't accurately compute response time.
            # We'll skip real calculation and return None or a placeholder.
            # response_time = "N/A"

        # Average Security: map severity levels to numbers and average them
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        approved_bugs_with_scores = approved_bugs.exclude(related_bounty__severity__isnull=True)
        if approved_bugs_with_scores.exists():
            severity_scores = [severity_map.get(b.related_bounty.severity, 1) for b in approved_bugs_with_scores]
            avg_security_score = sum(severity_scores) / len(severity_scores)
        else:
            avg_security_score = None

        return {
            "total_bug_approved": total_approved,
            "response_time": response_time,
            "average_security": avg_security_score
        }

    def get_hunter_performance_insight(self, user):
        # total bugs of his submission are approved
        approved_bugs = Bug.objects.filter(submitted_by=user, is_accepted=True)
        total_approved = approved_bugs.count()

        # Response time: similar issue as above, we need approved_at field
        # Assuming we had it, we would do something like:
        response_time = str(approved_bugs.aggregate(avg_time=Avg(F('approved_at') - F('submitted_at')))['avg_time'])
        response_time = "N/A" if response_time == "None" else str(response_time)

        
        # Average Security of approved bugs (based on bounty severity)
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        if total_approved > 0:
            severity_scores = [severity_map.get(b.related_bounty.severity, 1) for b in approved_bugs]
            avg_security_score = sum(severity_scores) / len(severity_scores)
        else:
            avg_security_score = None

        return {
            "total_bug_approved": total_approved,
            "response_time": response_time,
            "average_security": avg_security_score
        }
