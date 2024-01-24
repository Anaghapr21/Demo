from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from rest_framework import generics,status
from rest_framework.response import Response
# from rest_framework import status
from .models import SuperAdmin,UserRole,User,Employee
from .serializers import SuperAdminSerializer,UserRoleSerializer,UserSerializer,LoginSerializer,EmployeeSerializer
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import check_password
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken


class SuperAdminView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access for all methods

    def get(self, request):
        super_admin = SuperAdmin.objects.all()
        serializer = SuperAdminSerializer(super_admin, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = SuperAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserRoleView(APIView):
    permission_classes=[AllowAny]

    def get(self,request):
        user_roles=UserRole.objects.all()
        serializer=UserRoleSerializer(user_roles,many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer=UserRoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class UserRoleView(APIView):
#     queryset = UserRole.objects.all()
#     serializer_class = UserRoleSerializer
#     def get(self, request, *args, **kwargs):
#         user_roles = UserRole.objects.all()
#         serializer = UserRoleSerializer(user_roles, many=True)
#         return Response(serializer.data, status=status.HTTP_200_OK)

#     def post(self, request, *args, **kwargs):
#         serializer = UserRoleSerializer(data=request.data)

#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message": "User role created successfully."}, status=status.HTTP_201_CREATED)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    

class UserView(APIView):
    permission_classes=[AllowAny]
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def get(self, request, user_id, *args, **kwargs):
        user = self.get_user(user_id)
        if user is not None:
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, user_id, *args, **kwargs):
        user = self.get_user(user_id)

        if user is not None:
            serializer = UserSerializer(user, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({"message": "User updated successfully"}, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, user_id, *args, **kwargs):
        user = self.get_user(user_id)

        if user is not None:
            # Implement logical deletion or deactivation here
            user.delete()
            return Response({"message": "User deactivated successfully"}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)




# class LoginView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         serializer = LoginSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         username = serializer.validated_data['username']
#         password = serializer.validated_data['password']

#         # Check if a user with the provided username exists in the SuperAdmin model
#         try:
#             user = SuperAdmin.objects.get(username=username)
#         except SuperAdmin.DoesNotExist:
#             user = None

#         # If a user is found, check the password
#         if user and check_password(password, user.password):
#             # Password matches, generate a token for authentication
#             # login(request, user)
#             token, created = Token.objects.get_or_create(user=user)
#             return Response({'token': token.key}, status=status.HTTP_200_OK)
#         else:
#             return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password'] 

        # Check if a user with the provided username exists in the SuperAdmin model
        try:
            user = SuperAdmin.objects.get(username=username)
        except SuperAdmin.DoesNotExist:
            user = None

        # If a user is found, check the password
        if user and check_password(password, user.password):
            refresh = RefreshToken.for_user(user)
            return Response({'access_token': str(refresh.access_token)}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)




class UserLoginView(APIView):
    permission_classes=[AllowAny]

    def post(self,request,*args, **kwargs):
        serializer=LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username=serializer.validated_data['username']
        password=serializer.validated_data['password']

        try:
            user=User.objects.get(username=username)
        except User.DoesNotExist:
            user=None

        if user and check_password(password,user.password):
            refresh=RefreshToken.for_user(user)
            return Response({'access_token':str(refresh.access_token)},status=status.HTTP_200_OK)
        else:
            return Response({'error':'Invalid credentials'},status=status.HTTP_401_UNAUTHORIZED)


class EmployeeView(APIView):
    permission_classes=[AllowAny]
    def get_employee(self, employee_id):
        try:
            return Employee.objects.get(pk=employee_id)
        except Employee.DoesNotExist:
            return None

    def get(self, request, employee_id, *args, **kwargs):
        employee = self.get_employee(employee_id)
        if employee is not None:
            serializer = EmployeeSerializer(employee)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Employee not found"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, *args, **kwargs):
        serializer = EmployeeSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Employee created successfully"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, employee_id, *args, **kwargs):
        employee = self.get_employee(employee_id)

        if employee is not None:
            serializer = EmployeeSerializer(employee, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Employee updated successfully"}, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"message": "Employee not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, employee_id, *args, **kwargs):
        employee = self.get_employee(employee_id)

        if employee is not None:
            # Implement logical archive of employee accounts here
            employee.status = 'Archived'
            employee.save()
            return Response({"message": "Employee archived successfully"}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({"message": "Employee not found"}, status=status.HTTP_404_NOT_FOUND)