from rest_framework import viewsets, permissions, status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from rest_framework.views import APIView

from auth_core import settings
from .serializers import UserSerializer, loginSerializer
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
                    'token': str(refresh.access_token),
                    'user': user_data
                },
                status=status.HTTP_200_OK
            )
            response.set_cookie(
                key='refresh',
                value=str(refresh),
                httponly=True,
                secure=False,
                samesite=None,
                max_age=3600,
                path='/',
            )

            return response


class LogoutView(APIView):
    """
        ## Methods
            * POST /Logout
        ## Permissions
            * Authenticated User
        """

    permission_classes = (permissions.IsAuthenticated,)
    def post(self, request, *args, **kwargs):
        
        logout(request)
        return Response({"message": "Logout done successful !"},status=status.HTTP_204_NO_CONTENT)