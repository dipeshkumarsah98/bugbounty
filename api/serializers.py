from django.utils import timezone
from datetime import timedelta
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import get_user_model, authenticate
from .models import Bounty, Bug, Skill, Comment, RewardTransaction
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
    title = serializers.ReadOnlyField(source='related_bounty.title')
    description = serializers.ReadOnlyField(source='related_bounty.description')

    class Meta:
        model = Bug
        fields = ['id', 'title', 'description', 
                  'comments_count', 'submitted_by', 
                  'related_bounty', 'submitted_at', 'status',
                  'is_accepted', 'attachment', 'guide', 'expected_result',
                  ]
        read_only_fields = ['submitted_by', 'comments_count','is_accepted', 'status']

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
    title = serializers.ReadOnlyField(source='related_bounty.title')
    description = serializers.ReadOnlyField(source='related_bounty.description')
    class Meta:
        model = Bug
        fields = ['id', 'title', 'description', 'comments_count', 
                  'comments', 'submitted_by', 'related_bounty', 'status',
                  'submitted_at', 'is_accepted', 'attachment', 'guide', 'expected_result',
                  ]
        read_only_fields = ['submitted_by', 'comments_count', 'comments', 'related_bounty', 'is_accepted', 'status']

class BugStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Bug.STATUS_CHOICES)

    class Meta:
        model = Bug
        fields = ['id', 'status']

class RewardTransactionSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source='user.email')
    created_by = serializers.ReadOnlyField(source='created_by.email')
    class Meta:
        model = RewardTransaction
        fields = ['id', 'user', 'amount', 'transaction_type', 'created_at', 'created_by', 'note']
        read_only_fields = ['created_by', 'user']

class LeaderboardUserSerializer(serializers.ModelSerializer):
    net_reward = serializers.DecimalField(max_digits=10, decimal_places=2)
    solved_bugs = serializers.IntegerField()
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'net_reward', 'solved_bugs']

class RewardSummarySerializer(serializers.Serializer):
    current_reward = serializers.DecimalField(max_digits=10, decimal_places=2)
    total_reward = serializers.DecimalField(max_digits=10, decimal_places=2)
    transactions = RewardTransactionSerializer(many=True)

class TopHunterSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    hunter_name = serializers.CharField(max_length=255)
    net_reward = serializers.CharField(max_length=50)  # or DecimalField if preferred

class PerformanceInsightSerializer(serializers.Serializer):
    total_bug_approved = serializers.IntegerField()
    response_time = serializers.CharField(max_length=50, allow_null=True)
    average_security = serializers.FloatField(allow_null=True)

class DashboardActivitySerializer(serializers.Serializer):
    date = serializers.DateTimeField()
    action = serializers.CharField()

class DashboardSerializer(serializers.Serializer):
    active_bounties = serializers.IntegerField()
    my_token = serializers.CharField()
    top_hunter_of_the_month = TopHunterSerializer(allow_null=True)
    recent_activities = DashboardActivitySerializer(many=True)
    performance_insight = PerformanceInsightSerializer()

class RecentActivitySerializer(serializers.Serializer):
    date = serializers.DateTimeField()
    action = serializers.CharField()
    reward = serializers.DecimalField(max_digits=10, decimal_places=2, allow_null=True)

class HunterProfileSerializer(serializers.Serializer):
    name = serializers.CharField()
    email = serializers.EmailField()
    total_earned = serializers.DecimalField(max_digits=10, decimal_places=2)
    current_balance = serializers.DecimalField(max_digits=10, decimal_places=2)
    rank = serializers.IntegerField()
    solved_bugs = serializers.IntegerField()
    total_bugs_reported = serializers.IntegerField()
    success_rate = serializers.FloatField()
    recent_activities = RecentActivitySerializer(many=True)
