from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import *
import bcrypt

# Create your views here.
# ----------------------------------------ALL RENDERING----------------------------------------
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
            context = {
                "user" : User.objects.get(id=request.session['userID'])
            }
            return render (request,"users/home.html", context)

def admin(request):
    if 'userID' not in request.session:
        request.session.clear()
        return redirect("/")
    else:
        if request.session['user'] != 9:
            request.session.clear()
            return redirect("/breached")
        else:
            user = User.objects.get(id=request.session['userID'])
            if request.session['sID'] != hash(user.created_at):
                request.session.clear()
                return redirect('/breached')
            if request.session['user'] != user.user_level:
                request.session.clear()
                return redirect('/breached')
            else:
                context = {
                    "user" : user,
                    "users" : User.objects.order_by('-user_level')
                }
                return render(request,"users/admin.html", context)

def breached(request):
    print("*"*80,"\n","Security Breached","\n", "*"*80)
    request.session.clear()
    return HttpResponse("You do not have permission to perform this action.")

def user(request,id):
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
            context = {
            "user" : User.objects.get(id=id) 
            }
            return render (request, "users/user.html", context)
# ----------------------------------------END ALL RENDERING----------------------------------------
# ----------------------------------------LOGIN AND REGISTRATION----------------------------------------
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
# ----------------------------------------END LOGIN AND REGISTRATION----------------------------------------
def logout(request):
    request.session.clear()
    return redirect("/")
# ----------------------------------------ADMIN FORM----------------------------------------
def changetype(request):
    if request.method == "POST":
        user = User.objects.get(id = request.POST['userID'])
        if user.id == request.session["userID"]:
            messages.error(request,"You maynot change your own User Type", extra_tags="cantdothat")
            return redirect("/admin")
        else:
            if user.user_level == 1:
                user.user_level = 9
                user.save()
                return redirect("/admin")
            if user.user_level == 9:
                user.user_level = 1
                user.save()
                return redirect("/admin")
    else:
        request.session.clear()
        return redirect("/breached")

def deleteuser(request):
    if request.method == "POST":
        user = User.objects.get(id = request.POST['userID'])
        if user.user_level == 9:
            messages.error(request,"You maynot delete another Admin user", extra_tags="cantdothat")
            return redirect ("/admin")
        else:
            user.delete()
            return redirect ("/admin")
     
    else:
        request.session.clear()
        return redirect("/breached")
# ----------------------------------------ADMIN FORM----------------------------------------