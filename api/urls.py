from django.urls import path
from . import views

urlpatterns = [
    path('token/refresh/', views.CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('login/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('register/', views.UserRegistrationView.as_view(), name='user_registration'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('verify-otp/', views.OTPVerificationView.as_view(), name='otp_verification'),
]