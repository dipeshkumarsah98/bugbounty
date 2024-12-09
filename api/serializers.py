from django.utils import timezone
from datetime import timedelta
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import get_user_model, authenticate
from .models import Bounty, Bug, Skill, Comment
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
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ("name", "email", "role", 'skills', "industry", "password")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Remove the UniqueValidator from the email field
        self.fields['email'].validators = [
            validator for validator in self.fields['email'].validators
            if not isinstance(validator, UniqueValidator)
        ]

    def validate(self, data):
        if data["role"].lower() == "hunter":
            data["industry"] = ""
            if not data.get("skills"):
                raise serializers.ValidationError("Skill set is required for clients")

        if data["role"].lower() == "client":
            data["skills"] = []
            if not data.get("industry"):
                raise serializers.ValidationError("Industry is required for hunters")

        return data

    def validate_email(self, value):
        user = User.objects.filter(email=value).first();
        if user is None:
            return value

        if user and user.is_active:
            raise serializers.ValidationError('A user with this email already exists.')
        return value 
   
    def create(self, validated_data):
        email = validated_data['email']
        user = User.objects.filter(email=email).first()

        if user:
            # user.otp = str(random.randint(100000, 999999))
            user.otp = '123456' 
            user.otp_created_at = timezone.now()
            user.set_password(validated_data['password'])
            user.role = validated_data['role']
            user.skills.set(validated_data['skills'])
            user.name = validated_data['name']
            user.industry = validated_data['industry']
            #  skill is missing
            user.is_active = False  
            user.save()

            # Resend OTP email
            send_otp_email(user.email, user.name, user.otp)

            return user
        else:
            user = User.objects.create_user(
                role=validated_data["role"],
                email=email,
                name=validated_data["name"],
                password=validated_data["password"],
                industry=validated_data["industry"],
                is_active=False,
            )
            user.skills.set(validated_data["skills"])
            # otp = str(random.randint(100000, 999999))
            otp = '123456'
            send_otp_email(user.email, user.name, otp)

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

class BugSerializer(serializers.ModelSerializer):
    submitted_by = UserRegistrationSerializer(read_only=True)
    comments_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Bug
        fields = ['id', 'title', 'description', 
                  'comments_count', 'submitted_by', 
                  'related_bounty', 'submitted_at', 
                  'is_accepted', 'attachment', 'guide',
                  ]
        read_only_fields = ['submitted_by', 'comments_count']

class BountySerializer(serializers.ModelSerializer):
    created_by = UserRegistrationSerializer(read_only=True)
    bugs_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = Bounty
        fields = "__all__"
        read_only_fields = ['created_by', 'bugs']

class BountyDetailSerializer(serializers.ModelSerializer):
    created_by = UserRegistrationSerializer(read_only=True)
    bugs = BugSerializer(many=True, read_only=True)
    bugs_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = Bounty
        fields = "__all__"
        read_only_fields = ['created_by', 'bugs', 'bugs_count']

class SkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = "__all__"

class CommentSerializer(serializers.ModelSerializer):
    user = UserRegistrationSerializer(read_only=True)
    class Meta:
        model = Comment
        fields = ['id', 'user', 'text', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']

class BugDetailSerializer(serializers.ModelSerializer):
    comments = CommentSerializer(many=True, read_only=True)
    comments_count = serializers.IntegerField(read_only=True)
    submitted_by = UserRegistrationSerializer(read_only=True)
    related_bounty = BountySerializer(read_only=True)
    class Meta:
        model = Bug
        fields = ['id', 'title', 'description', 'comments_count', 
                  'comments', 'submitted_by', 'related_bounty', 
                  'submitted_at', 'is_accepted', 'attachment', 'guide'
                  ]
        read_only_fields = ['submitted_by', 'comments_count', 'comments', 'related_bounty']