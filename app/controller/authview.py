from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout, update_session_auth_hash
from django.contrib.auth.models import User

from django.shortcuts import redirect, render

from app.forms import Costomuserform, UserPasswordChangeForm, UserChangePassword,UserforgetPassword
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail,EmailMessage
from app.token import generate_token

# email threding
import threading
class EmailThread(threading.Thread):
    def __init__ (self,email):
        self.email=email
        threading.Thread.__init__ (self)
    def run(self):
        self.email.send()


def register(request):
    if request.user.is_authenticated:
        messages.warning(request, "You Are Already Logged In")
        return redirect("/")
    else:
        form=Costomuserform()
        if request.method =='POST':
            form=Costomuserform(request.POST)
            if form.is_valid():
                username=request.POST.get('username')
                email=request.POST.get('email')
                passwd=request.POST.get('password1')
                myuser=User.objects.create_user(username,email,passwd)
                myuser.is_active = False
                myuser.save()
                messages.success(request, "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
                
                # Welcome Email
                subject = "Welcome to BALIRAJA !!"
                message = "Hello " + myuser.email + "!! \n" + "Welcome to BALIRAJA !! \nThank you for visiting our website\nWe have also sent you a confirmation email, please confirm your email address to login. \n\nThanking You\n BaliRaja Er.Sanket Agre"        
                from_email = settings.EMAIL_HOST_USER
                to_list = [myuser.email]
                send_mail(subject, message, from_email, to_list, fail_silently=True)
                
                # # Email Address Confirmation Email
                current_site = get_current_site(request)
                email_subject = "Confirm your Email @ BALIRAJA !!"
                message2 = render_to_string('auth/email_confirmation.html',{
                    
                    'name': myuser.username,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                    'token': generate_token.make_token(myuser)
                })
                email = EmailMessage(
                email_subject,
                message2,
                settings.EMAIL_HOST_USER,
                [myuser.email],
                )
                email.fail_silently = True
                EmailThread(email).start()
                messages.success(request, "Registration Successfully! Login to continue")
                return render(request, "auth/login.html")
        context={'form':form}
        return render(request, "auth/register.html",context )


def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect("/")
    else:
        messages.success(request, "please verify your email to continue !!")
        return redirect("/")


def loginpage(request):
    if request.user.is_authenticated:
        messages.warning(request, "You Are Already Logged In")
        return redirect("/")
    else:
        if request.method=='POST':
            name=request.POST.get('username')
            passwd=request.POST.get('password')
            user=authenticate(request,username=name, password=passwd)
            
            if user is not None:
                login(request, user)
                messages.success(request, 'logged in successfully')
                return redirect("/")
            else:
                
                messages.error(request, "Invalid Username or Password Or Email is not verified")
                return redirect("/login")

    return render(request, "auth/login.html")


def logoutpage(request):
    if request.user.is_authenticated:
        logout(request)
        messages.success(request,"Logged OUT successfully")
        return redirect("/")
    
# change password with old password

def changepass(request):
    if request.user.is_authenticated:
        if request.method== "POST":
            form=UserPasswordChangeForm(user=request.user, data=request.POST)
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, form.user)
                messages.success(request, 'password change successfully')
                return redirect('/')
            else:
                messages.success(request, 'please Enter Valid Data ')
                return redirect('changepass')
        form=UserPasswordChangeForm(user=request.user)
        context={'form':form}
        return render(request, 'auth/changepasswitholdpass.html', context )
    else:
        messages.success(request, 'Please Login to Continue')
        return redirect('loginpage')
    


def forgetpass(request):
    if request.method == "POST":
        form=UserforgetPassword(request.POST)
        if form.is_valid():
            username=request.POST.get('username')

            user_obj=User.objects.filter(username=username).first()

            if user_obj is not None:
                current_site = get_current_site(request)
                email_subject = "Click on link to reset your password Email @ BALIRAJA !!"
                message3 = render_to_string('auth/email_forgetpass.html',{
                    
                    'name': user_obj.username,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user_obj.pk)),
                    'token': generate_token.make_token(user_obj)
                })
                email = EmailMessage(
                email_subject,
                message3,
                settings.EMAIL_HOST_USER,
                [user_obj.email],
                )
                email.fail_silently = True
                EmailThread(email).start()
                # email.send()
                messages.success(request, "verify your email and reset your password ")
                return redirect("/")
            print('object not found')
    form=UserforgetPassword()
    return render(request, 'auth/forgetpassword.html', {'form':form})


def set_password(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        form=UserChangePassword()
        if request.method =='POST':
            form=UserChangePassword(request.POST)
            if form.is_valid():
                password1=request.POST.get('new_password1')
                password2=request.POST.get('new_password2')

                if password1 == password2:
                    myuser.set_password(password1)
                    myuser.save()
                    messages.success(request, "Password Reset Successfuly. Login to continue!!")
                    return redirect("loginpage")
                else:
                    messages.error(request, "new password is not match with confirm password !!")
        
        return render(request, "auth/changeforgetpassword.html", {'form':form})
        
    else:
        messages.success(request, "Your Account not activated!!")
        return redirect("/")