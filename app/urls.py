from unicodedata import name
from django.contrib import admin
from django.urls import path
from app import views
from app.controller import authview


urlpatterns = [
    path("",views.index, name="home"),

    path("register", authview.register, name='register'),
    path("login", authview.loginpage, name="loginpage"),
    path("logout", authview.logoutpage, name="logout"),
    
    path('activate/<uidb64>/<token>', authview.activate, name='activate'),
    path('set_password/<uidb64>/<token>', authview.set_password, name='set_password'),

    path('changepass', authview.changepass, name="changepass"),
    path('forgetpass', authview.forgetpass, name="forgetpass"),

]
