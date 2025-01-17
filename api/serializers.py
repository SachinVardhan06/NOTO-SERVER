from rest_framework import serializers
from .models import User, Subscription

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return user

class SubscriptionSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    time_left = serializers.ReadOnlyField()

    class Meta:
        model = Subscription
        fields = ['id', 'user', 'membership_type', 'purchase_date', 'start_date', 'end_date', 'time_left']
