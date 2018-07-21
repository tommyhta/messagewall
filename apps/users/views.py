from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
import re
import bcrypt
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z._-]+\.[a-zA-Z]+$')
from .models import *
# Create your views here.


def index(request):
    return HttpResponse("splash placeholder")

def breached(request):
    return HttpResponse("Wtf bruh..")

def logorreg(request):
    return render(request, "users/login.html")

def logout(request):
    request.session.clear()
    return redirect('/logorreg')

def welcome(request):
    if 'userID' not in request.session:
        request.session.clear()
        return redirect ('/logorreg')
    else:
        user = User.objects.get(id=request.session['userID'])
        if request.session['sID'] != hash(user.created_at):
            request.session.clear()
            return redirect('/breached')
        else:
            context = {
                "user" : user,
                "post" : Post.objects.all(),
                "comment" : Comment.objects.all()
            }
            return render (request, "users/wall.html",context)

def register(request):
    if request.method == 'POST':
        enteredFirstName = request.POST['first_name']
        enteredLastName = request.POST['last_name']
        enteredEmail = request.POST['email']
        enteredPassword = request.POST['password']
        enteredConfirmation = request.POST['passwordCon']
        count=0
        if len(enteredFirstName) <1:
            messages.error(request, "This field cannot be empty.", extra_tags="first_name")
            count+=1
        elif len(enteredFirstName) <2:
            messages.error(request, "Name must be longer.", extra_tags="first_name")
            count+=1
            print("~*"*40)
        elif not str.isalpha(enteredFirstName):
            messages.error(request, "Name may not contain numbers.", extra_tags="first_name")
            count+=1
        if len(enteredLastName) <1:
            messages.error(request, "This field cannot be empty.", extra_tags="last_name")
            count+=1
        elif len(enteredLastName) <2:
            messages.error(request, "Name must be longer.", extra_tags="last_name")
            count+=1
        elif not str.isalpha(enteredLastName):
            messages.error(request, "Name may not contain numbers.", extra_tags="last_name")
            count+=1
        if len(enteredEmail) < 1:
            messages.error(request, "This field cannot be empty.", extra_tags="email")
            count+=1
        elif not email_regex.match(enteredEmail):
            messages.error(request, "Please enter a valid email address.", extra_tags="email")
            count+=1
        elif len(User.objects.filter(email=enteredEmail)):
            messages.error(request, "Please use a different email address.", extra_tags="email")
            count+=1
        if len(enteredPassword) < 1 :
            messages.error(request, "This field cannot be empty.", extra_tags="password")
            count+=1
        elif len(enteredPassword)<8:
            messages.error(request, "Password must have more than 8 characters.", extra_tags="password")
            count+=1
        elif not re.search(r'[A-Z]+', enteredPassword):
            messages.error(request, "Password must contain an uppercase letter.", extra_tags="password")
            count+=1
        elif not re.search(r'[0-9]+', enteredPassword):
            messages.error(request, "Password must contain a number.", extra_tags="password")
            count+=1
        if len(enteredConfirmation) <1:
            messages.error(request, "This field cannot be empty.", extra_tags="confirm")
            count+=1
        elif enteredConfirmation != request.POST['password']:
            messages.error(request, "Password confirmation must match password.", extra_tags="confirm")
            count+=1
        if count > 0:
            return redirect ('/logorreg')
        else:
            pwhas = bcrypt.hashpw(enteredPassword.encode(), bcrypt.gensalt())
            User.objects.create(first_name=enteredFirstName, last_name=enteredLastName, email=enteredEmail, password_hash=pwhas, user_level = 1)
            user = User.objects.get(email = enteredEmail)
            request.session['name'] = user.first_name
            request.session['user'] = user.user_level
            request.session['userID'] = user.id
            request.session['sID'] = hash(user.created_at)
            return redirect("/welcome")
    else:
        request.session.clear()   
        return redirect('/logorreg')
        
def login(request):
    if request.method == 'POST':
        email = request.POST['emaillogin']
        password = request.POST['passwordlogin']
        if len(email) < 1:
            messages.error(request,"Please insert your email.", extra_tags="loginE")
        if len(password) < 1:
            messages.error(request,"Please insert your password.", extra_tags="needed")
            return redirect("/logorreg")
        else:
            if len(User.objects.filter(email=request.POST['emaillogin']))==0:
                messages.error(request,"You cannot be logged in.", extra_tags="bad")
                request.session.clear()
                return redirect("/logorreg")
            else:
                user = User.objects.get(email=request.POST['emaillogin'])    
                if bcrypt.checkpw(request.POST['passwordlogin'].encode(), user.password_hash.encode()):
                    user = User.objects.get(email=request.POST['emaillogin'])
                    request.session['name'] = user.first_name
                    request.session['user'] = user.user_level
                    request.session['userID'] = user.id
                    request.session['sID'] = hash(user.created_at)
                    return redirect('/welcome')
                else:
                    messages.error(request,"You cannot be logged in.", extra_tags="bad")
                    request.session.clear()
                    return redirect("/logorreg")    
    else:
        request.session.clear()
        return redirect('/logorreg')

def post(request):
    if request.method == "POST":
        if request.session['userID']!= int(request.POST['user']):
            request.session.clear()
            return redirect ("/breached")
        else:
            if len(request.POST['post'])<1:
                messages.error(request,"Message cannot be blank.", extra_tags="post")
                return redirect("/welcome")
            elif len(request.POST['post'])>700:
                messages.error(request,"Message cannot be more than 700 characters.", extra_tags="post")    
                return redirect("/welcome")
            else:
                user = User.objects.get(id=request.session['userID'])
                Post.objects.create(content=request.POST['post'], writer=user)
                return redirect("/welcome")
    else:
        return redirect ("/welcome")
    
def delpost(request):
    if request.method == "POST":
        post = Post.objects.get(id=request.POST['delPost'])
        if request.session['userID'] !=post.writer.id:
            request.session.clear()
            return redirect ("/breached")
        else:
            post.delete()
            return redirect("/welcome")
    else:
        return redirect ("/welcome")

def comment(request):
    if request.method == "POST":
        post = Post.objects.get(id=request.POST['posted'])
        user = User.objects.get(id=request.session['userID'])
        if len(request.POST['comment'])<1:
            messages.error(request,"Please enter a comment.",extra_tags="comment")
            return redirect("/welcome")
        elif len(request.POST['comment'])>255:
            messages.error(request,"Message cannot be more than 255 characters.", extra_tags="comment")
            return redirect("/welcome")
        else:
            Comment.objects.create(content=request.POST['comment'], posted=post,written=user)
            return redirect("/welcome")
    else:
        return redirect("/welcome")

def delcom(request):
    if request.method == "POST":
        comment = Comment.objects.get(id=request.POST['comDel'])
        if request.session['userID'] != comment.written.id:
            request.session.clear()
            return redirect("/breached")
        else:
            comment.delete()
            return redirect ("/welcome")
    else:
        return redirect("/welcome")    