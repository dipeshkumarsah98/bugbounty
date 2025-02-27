from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from api.views import SkillViewSet, BountyViewSet, BugViewSet, BugCommentListCreateView, BugStatusView, RewardTransactionViewSet, WithdrawRewardViewSet, LeaderboardView, DashboardView, HunterProfileView, CurrentUserProfileView
from .view import APIRootView
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

schema_view = get_schema_view(
   openapi.Info(
      title="BugBounty API",
      default_version='v1',
      description="API documentation for BugBounty Platform",
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

router = routers.DefaultRouter()
router.register(r'skills', SkillViewSet, basename='skill')
router.register(r'bounties', BountyViewSet, basename='bounty')
router.register(r'bugs', BugViewSet, basename='bug')
router.register(r'rewards', RewardTransactionViewSet, basename='reward')
router.register(r'withdraw', WithdrawRewardViewSet, basename='withdraw')

urlpatterns = [
    path('', APIRootView.as_view(), name='api-list'),
    path('admin/', admin.site.urls),
    path('api/', APIRootView.as_view(), name='api-root'),
    path('api/', include(router.urls)),  
    path('api/auth/', include('api.urls')),  
    path('api/bugs/<int:bugid>/comments', BugCommentListCreateView.as_view(), name='bug-comments-list-create'),
    path('api/bugs/<int:bugid>/status', BugStatusView.as_view(), name='bug-status-create'),
    path('api/hunters/<int:id>/profile/', HunterProfileView.as_view(), name='hunter-profile'),
    path('api/profile/', CurrentUserProfileView.as_view(), name='profile'),
    path('api/leaderboard/', LeaderboardView.as_view(), name='leaderboard'),
    path('api/dashboard/', DashboardView.as_view(), name='dashboard'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
