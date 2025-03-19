from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes

from django.contrib.auth.models import User
from .models import Profile
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """ Serializer for User model """
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name = validated_data['last_name'],
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class loginSerializer(serializers.Serializer):
    """ Login Serializer """
    username = serializers.CharField()
    password = serializers.CharField()


class ProfileSerializer(serializers.ModelSerializer):
    """ Show profile Serializer """
    class Meta:
        model = Profile
        fields = ['avatar', 'username', 'email', 'first_name', 'last_name', 'bio']


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """ Update Profile Serializer """
    class Meta:
        model = Profile
        fields = ['avatar', 'email', 'first_name', 'last_name', 'bio']


class ChangePasswordSerializer(serializers.Serializer):
    """ Change connected User Password Serializer """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords didn't match.")
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        if not user.check_password(self.validated_data['old_password']):
            raise serializers.ValidationError("Incorrect old password.")
        user.set_password(self.validated_data['new_password'])
        user.save()
        self.context['request'].session.save()
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    """ Request Password Reset Serializer """
    email = serializers.EmailField()

    def validate_email(self, value):
        """ Vérifie si l'email existe dans la base de données """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Not accounts associated with this email.")
        return value

    def save(self):
        """ Generate a token and send Email verification """
        email = self.validated_data["email"]
        user = User.objects.get(email=email)

        # Generation of token
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Reset passwork link
        reset_link = f"http://127.0.0.1:8000/accounts/reset-password/{uid}/{token}/"

        # Send EMail method
        user.email_user(
            "Réinitialisation de votre mot de passe",
            f"Bonjour, \n\nCliquez sur le lien ci-dessous pour réinitialiser votre mot de passe :\n{reset_link}\n\nSi vous n'avez pas demandé ce changement, ignorez cet email."
        )
        return reset_link


class PasswordResetConfirmSerializer(serializers.Serializer):
    """ Reset Password Confirmation Serializer """
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords don't match.")
        return data

    def save(self, uid, token):
        """ Token verification and password reset """
        try:
            user_id = force_bytes(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid link or expired.")

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            raise serializers.ValidationError("Invalid reset link or expired.")

        # Mise à jour du mot de passe
        user.set_password(self.validated_data["new_password"])
        user.save()
        return user