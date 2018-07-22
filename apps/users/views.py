from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import *
import bcrypt

# Create your views here.
# ALL RENDERING
def index(request):
    return render(request,"users/index.html")

def welcome(request):
# security check for a page
    if 'userID' not in request.session:
        request.session.clear()
        return redirect("/")
    else:
        user = User.objects.get(id=request.session['userID'])
        if request.session['sID'] != hash(user.created_at):
            request.session.clear()
            return redirect('/breached')
        if request.session['user'] != user.user_level:
            request.session.clear()
            return redirect('/breached')
        else:
# clear to proceed
            return HttpResponse("Welcome")

def breached(request):
    return HttpResponse("You do not have permission to perform this action.")
# ----------------------------------------END ALL RENDERING----------------------------------------
# LOGIN AND REGISTRATION
def register(request):
    if request.method == 'POST':
        error = User.objects.validator(request.POST)
        if len(error):
            for key,value in error.items():
                messages.error(request, value, extra_tags=key)
            return redirect("/")
        else:
            pwhash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            User.objects.create(
                first_name = request.POST['first_name'],
                last_name = request.POST['last_name'],
                email = request.POST['email'],
                user_level = 1,
                password_hash = pwhash
            )
            user = User.objects.get(email=request.POST['email'])
            request.session['name'] = user.first_name
            request.session['user'] = user.user_level
            request.session['userID'] = user.id
            request.session['sID'] = hash(user.created_at)
            return redirect("/welcome")
    else:
        request.session.clear()
        return redirect("/")

def login(request):
    if request.method == 'POST':
        error = User.objects.loginValidator(request.POST)
        if len(error):
            for key,value in error.items():
                messages.error(request, value, extra_tags=key)
            return redirect("/")
        else:
            if len(User.objects.filter(email=request.POST['emaillogin']))==0:
                messages.error(request,"You cannot be logged in.", extra_tags="bad")
                request.session.clear()
                return redirect("/")
            else:
                user = User.objects.get(email=request.POST['emaillogin'])    
                if bcrypt.checkpw(request.POST['key'].encode(), user.password_hash.encode()):
                    request.session['name'] = user.first_name
                    request.session['user'] = user.user_level
                    request.session['userID'] = user.id
                    request.session['sID'] = hash(user.created_at)
                    return redirect("/welcome")    
                else: 
                    messages.error(request,"You cannot be logged in.", extra_tags="bad")
                    request.session.clear()
                    return redirect("/")       
    else:
        request.session.clear()
        return redirect("/")
# END LOGIN AND REGISTRATION
def logout(request):
    request.session.clear()
    return redirect("/")