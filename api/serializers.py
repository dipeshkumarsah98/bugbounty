import random
from django.utils import timezone
from datetime import timedelta
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from .models import Bounty, Bug, Skill
from .utils import send_otp_email, send_welcome_email

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = User.USERNAME_FIELD

    def validate(self, attrs):
        credentials = {"email": attrs.get("email"), "password": attrs.get("password")}

        user = authenticate(
            request=self.context.get("request"),
            email=credentials.get("email"),
            password=credentials.get("password"),
        )

        if not user or not user.is_active:
            raise serializers.ValidationError("Invalid credentials")

        data = super().validate(attrs)
        data["role"] = user.role
        data["email"] = user.email
        data["name"] = user.name
        return data

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)

    class Meta:
        model = User
        fields = ("name", "email", "role", "industry", "password")

    def create(self, validated_data):
        user = User.objects.create_user(
            role=validated_data["role"],
            email=validated_data["email"],
            name=validated_data["name"],
            password=validated_data["password"],
            industry=validated_data["industry"],
            is_active=False,
        )
        otp = str(random.randint(100000, 999999))
        send_otp_email(user.email, user.email, otp)

        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()
        return user

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, attrs):
        email = attrs.get("email")
        otp = attrs.get("otp")

        try:
            user = User.objects.get(email=email, otp=otp)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP or email")

        if user.otp_created_at < timezone.now() - timedelta(minutes=5):
            raise serializers.ValidationError("OTP has expired")

        return attrs

    def save(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)
        user.is_active = True
        user.otp = ""
        user.otp_created_at = None
        user.save()

        send_welcome_email(user.email, user.email, user.role)

        return user

class BountySerializer(serializers.ModelSerializer):
    class Meta:
        model = Bounty
        fields = "__all__"

class BugSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bug
        fields = "__all__"

class SkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = "__all__"
