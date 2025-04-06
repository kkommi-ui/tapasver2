from django.shortcuts import render, redirect, get_object_or_404
from .models import Dish, Account
from django.contrib import messages
from django.contrib.auth.hashers import make_password, check_password

def better_menu(request):
    dish_objects = Dish.objects.all()
    return render(request, 'tapasapp/better_list.html', {'dishes': dish_objects})

def add_menu(request):
    if request.method == "POST":
        dishname = request.POST.get('dname')
        cooktime = request.POST.get('ctime')
        preptime = request.POST.get('ptime')
        Dish.objects.create(name=dishname, cook_time=cooktime, prep_time=preptime)
        return redirect('better_menu')
    return render(request, 'tapasapp/add_menu.html')

def view_detail(request, pk):
    d = get_object_or_404(Dish, pk=pk)
    return render(request, 'tapasapp/view_detail.html', {'d': d})

def delete_dish(request, pk):
    Dish.objects.filter(pk=pk).delete()
    return redirect('better_menu')

def update_dish(request, pk):
    if request.method == "POST":
        cooktime = request.POST.get('ctime')
        preptime = request.POST.get('ptime')
        Dish.objects.filter(pk=pk).update(cook_time=cooktime, prep_time=preptime)
        return redirect('view_detail', pk=pk)
    d = get_object_or_404(Dish, pk=pk)
    return render(request, 'tapasapp/update_menu.html', {'d': d})

def login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = Account.objects.get(username=username)
            if check_password(password, user.password):
                request.session["user_id"] = user.id
                return redirect("basic_list", pk=user.id)
            else:
                messages.error(request, "Invalid Password")
                return redirect("login")  
        except Account.DoesNotExist:
            messages.error(request, "Invalid Username")
            return redirect("login")  

    return render(request, "tapasapp/login.html")

def basic_list(request, pk):
    user = get_object_or_404(Account, pk=pk) 
    return render(request, 'tapasapp/basic_list.html', {'user': user})

def signup(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        if Account.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
        else:
            hashed_password = make_password(password)
            new_account = Account.objects.create(username=username, password=hashed_password)
            messages.success(request, "Account created successfully!")
            return redirect("login")

    return render(request, "tapasapp/signup.html")

def manage_account(request, pk):
    user = get_object_or_404(Account, pk=pk)
    return render(request, 'tapasapp/manage_account.html', {'user': user})

def change_password(request, pk):
    user_id = request.session.get("user_id")
    if not user_id or int(pk) != user_id:
        return redirect("login")

    user = get_object_or_404(Account, pk=pk)

    if request.method == "POST":
        current_password = request.POST.get("current_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        if not check_password(current_password, user.password):
            messages.error(request, "Incorrect current password.")
            return redirect("change_password", pk=pk)

        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect("change_password", pk=pk)

        user.password = make_password(new_password)
        user.save()
        messages.success(request, "Password changed successfully!")
        return redirect("manage_account", pk=pk)

    return render(request, "tapasapp/change_password.html", {'user': user})

def delete_account(request, pk):
    user = get_object_or_404(Account, pk=pk)
    user.delete()
    messages.success(request, "Account deleted successfully.")
    return redirect("signup")

def logout(request):
    request.session.flush()  
    return redirect("login")  