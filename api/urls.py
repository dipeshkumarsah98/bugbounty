from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

urlpatterns = [
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/register/', views.UserRegistrationView.as_view(), name='user_registration'),
    path('api/logout/', views.LogoutView.as_view(), name='logout'),
    path('api/verify-otp/', views.OTPVerificationView.as_view(), name='otp_verification'),
    path('api/skills/', views.SkillViewSet.as_view({'get': 'list'}), name='skills'),
]