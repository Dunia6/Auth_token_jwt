from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerializer, loginSerializer, ProfileSerializer, ProfileUpdateSerializer, \
    ChangePasswordSerializer
from accounts.models import User, Profile

# Create your views here.

class RegisterViewSet(viewsets.ModelViewSet):
    """
    ## Champs
        * username
        * email
        * first_name
        * last_name
        * password
        * password2
    ## Methods
        * POST /register
    ## Permissions
        * AllowAny
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    http_method_names = ['post']


class LoginView(APIView):
    """
    ## Champs
        * username
        * password
    ## Methods
        * POST /Login
    ## Permissions
        * AllowAny
    """
    permission_classes = (permissions.AllowAny,)
    serializer_class = loginSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            username = serializer.data['username']
            password = serializer.data['password']

            if username is None or password is None:
                return Response({'error': 'username or password is required'}, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(username=username, password=password)
            if user is None:
                return Response({'error': 'invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

            refresh = RefreshToken.for_user(user)


            user_data = UserSerializer(user).data

            response = Response(
                {
                    'access_token': str(refresh.access_token),
                    'user': user_data
                },
                status=status.HTTP_200_OK
            )
            response.set_cookie(
                key='refresh_token',
                value=str(refresh),
                httponly=True,
                secure=False,
                samesite=None,
                max_age=3600,
                path='/',
            )

            return response


class RefreshAccessTokenView(APIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token")

        if refresh_token is None:
            return Response({'error': 'no refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)

            return Response({'access_token': new_access_token})
        except Exception:
            return Response({'error': 'invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
        ## Methods
            * POST /Logout
        ## Permissions
            * Authenticated User
        """
    permission_classes = (permissions.IsAuthenticated,)
    def post(self, request, *args, **kwargs):
        response = Response({"message": "Logout done successful !"},status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie(key='refresh_token')
        return response


class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ProfileSerializer
    http_method_names = ['get']

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)


class UserProfileUpdateViewSet(viewsets.ModelViewSet):
    """
    ## Champs
        * avatar {image}
        * email {email : example@example.com}
        * first_name {string}
        * last_name {string}
        * bio {string}
    ## Methods
        * PUT /UserProfileUpdate
    ## Permissions
        Authenticated User
    """
    queryset = Profile.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ProfileUpdateSerializer

    def update(self, request, *args, **kwargs):
        profile = get_object_or_404(Profile, user=self.request.user)
        serializer = self.get_serializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordViewSet(viewsets.ModelViewSet):
    """
    Change password

    parameters:
        old_password: string
        new_password: string
        confirm_password: string

    returns:
        detail: string

    """
    permission_classes = [permissions.IsAuthenticated,]
    serializer_class = ChangePasswordSerializer
    http_method_names = ['post']

    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """
        Met à jour le mot de passe de l'utilisateur connecté.
        """
        serializer = self.get_serializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Mot de passe modifié avec succès."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)