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
                "user" : User.objects.get(id=request.session['userID']),




# ----------------------------------------FOR EXAM----------------------------------------
                "quotes" : Quote.objects.all(),
# ----------------------------------------FOR EXAM----------------------------------------
                



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
            user = User.objects.get(id=id)
            context = {
            "user" : User.objects.get(id=id),




            "quotes" : Quote.objects.filter(uploaded = user)






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
# ----------------------------------------BELOW ARE THINGS FOR THE EXAM----------------------------------------

def addquote(request):
    if request.method == "POST":
        count = 0
        if len(request.POST['author'])<1:
            messages.error(request,"Author cannot be blank", extra_tags="author")
            count+=1
        elif len(request.POST['author'])<3:
            messages.error(request,"Author should have at least 3 characters", extra_tags="author")
            count+=1
        if len(request.POST['quote'])<1:
            messages.error(request,"Quote cannot be blank", extra_tags="quote")
            count+=1
        elif len(request.POST['quote'])<10:
            messages.error(request,"Quote should have at least 10 characters", extra_tags="quote")
            count+=1
        if count > 0:
            return redirect("/welcome")
        else:
            user = User.objects.get(id=request.session['userID'])
            author = Author.objects.create(
                name = request.POST['author'],
                added = user
            )
            quote = Quote.objects.create(
                content = request.POST['quote'],
                written = author,
                uploaded = user
            )
            return redirect("/welcome")
    else:
        return redirect("/welcome")

def deletequote(request):
    if request.method == "POST":
        quote = Quote.objects.get(id=request.POST['quote'])
        if quote.uploaded.id != request.session['userID']:
            return redirect("/breached")
        else:
            quote.delete()
            return redirect('/welcome')
    else:
        request.session.clear()
        return redirect("/breached")

def edituser(request,id):
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
            context={
                "user" : user
            }
            return render(request, "users/edituser.html", context)

def changeuser(request):
    if request.method == "POST":
        count=0
        enteredFirstName = request.POST['first_name']
        enteredLastName = request.POST['last_name']
        enteredEmail = request.POST['email']
        if len(enteredFirstName) <1:
            messages.error(request, "First name cannot be empty.", extra_tags="one")
            count+=1
        elif len(enteredFirstName) <2:
            messages.error(request, "First name must be longer.", extra_tags="one")
            count+=1
            print("~*"*40)
        elif not str.isalpha(enteredFirstName):
            messages.error(request, "First name may not contain numbers.", extra_tags="one")
            count+=1
        if len(enteredLastName) <1:
            messages.error(request, "Last name cannot be empty.", extra_tags="two")
            count+=1
        elif len(enteredLastName) <2:
            messages.error(request, "Last name must be longer.", extra_tags="two")
            count+=1
        elif not str.isalpha(enteredLastName):
            messages.error(request, "Last name may not contain numbers.", extra_tags="two")
            count+=1
        if len(enteredEmail) < 1:
            messages.error(request, "Email cannot be empty.", extra_tags="three")
            count+=1
        elif not email_regex.match(enteredEmail):
            messages.error(request, "Please enter a valid email address.", extra_tags="three")
            count+=1
        elif len(User.objects.filter(email=enteredEmail)):
            messages.error(request, "Please use a different email address.", extra_tags="three")
            count+=1
        if count > 0:
            return redirect("edituser", id=request.session['userID'])
        else:
            user = User.objects.get(id=request.session['userID'])
            user.first_name = enteredFirstName
            user.last_name = enteredLastName
            user.email = enteredEmail
            user.save()
            return redirect ("user", id=request.session['userID'])
    else:
        request.session.clear()
        return redirect("/breached")


def changepassword(request):
    if request.method == "POST":
        enteredPassword = request.POST['password']
        enteredConfirmation = request.POST['confirm']
        count = 0
        if len(enteredPassword) < 1 :
            messages.error(request, "Password cannot be empty.", extra_tags="four")
            count+=1
        elif len(enteredPassword)<8:
            messages.error(request, "Password must have more than 8 characters.", extra_tags="four")
            count+=1
        elif not re.search(r'[A-Z]+', enteredPassword):
            messages.error(request, "Password must contain an uppercase letter.", extra_tags="four")
            count+=1
        elif not re.search(r'[0-9]+', enteredPassword):
            messages.error(request, "Password must contain a number.", extra_tags="four")
            count+=1
        if len(enteredConfirmation) <1:
            messages.error(request, "Password Confirmation cannot be empty.", extra_tags="five")
            count+=1
        elif enteredConfirmation != request.POST['password']:
            messages.error(request, "Password confirmation must match password.", extra_tags="five")
            count+=1
        if count > 0:
            return redirect("edituser", id=request.session['userID'])
        else:
            user = User.objects.get(id=request.session['userID'])
            pwhash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
            user.password_hash = pwhash
            user.save()
            return redirect ("user", id=request.session['userID'])

    else:
        request.session.clear()
        return redirect("/breached")

def like(request,id):
    if request.method == "POST":
        quote = Quote.objects.get(id=id)
        user = User.objects.get(id=request.session['userID'])
        quote.likes.add(user)
        return redirect ("/welcome")
    else:
        request.session.clear()
        return redirect ("/breached")
    