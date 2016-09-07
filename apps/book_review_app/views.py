from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from  datetime import datetime
import bcrypt
import re
from django.contrib.auth import authenticate
from .models import User, Book, Review
import re
r = re.compile("^[a-zA-Z ]*$")

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
#Our new manager!
def check_password(email, password):
      u = User.objects.filter(email=email).first()
      if u == None:
          return None
      hashed = u.password
      if bcrypt.hashpw(password.encode("utf-8"), hashed.encode("utf-8")) == hashed.encode("utf-8"):
        print "It matches"
        return u
      else:
        print "It does not match"
        return None

def index(request):
  return render(request, "book_review_app/index.html")

def login(request):
    error = None
    email = request.POST['email']
    password = request.POST['password']
    if len(email) < 1:
       error="error"
       messages.add_message(request, messages.ERROR, 'email can not be blank! ')
    else:
       if not EMAIL_REGEX.match(email):
         error="error"
         messages.add_message(request, messages.ERROR, 'Invalid Email Address! ')
    if len(password) < 8:
        messages.add_message(request, messages.ERROR, 'Password has to be at least 8 characters! ')
        error="error"
    if error != None:
        context = {
            "category": "login"
        }
        return render(request, 'book_review_app/index.html', context)
    user = check_password(email=email, password=password)
    if user != None:
        print "after check_password:"
        request.session['user_id'] = user.id
        request.session['user_name'] = user.name
        context = {
          "reviews_first3": Review.objects.all()[:3],#User.objects.get(id=user.id)
          "review_others": Review.objects.all()[4:]
        }
        print Review.objects.all()[:3]
        print Review.objects.all()[4:]
        return render(request, 'book_review_app/books.html', context)
    else:
        context = {
            "category": "login"
        }
        messages.add_message(request, messages.ERROR, "Not registered, please register!")
        return render(request, 'book_review_app/index.html', context)

# def hasSpaceAndAlpha(string):
#     return any(char.isalpha() for char in string) and any(char.isspace() for char in string) and all(char.isalpha() or char.isspace() for char in string)

def registration(request):
        error = None
        name = request.POST['name']
        alias = request.POST['alias']
        email = request.POST['email']
        password = request.POST['password']
        if len(email) < 1:
           error="error"
           messages.add_message(request, messages.ERROR, 'email can not be blank! ')
        else:
           if not EMAIL_REGEX.match(email):
             error="error"
             messages.add_message(request, messages.ERROR, 'Invalid Email Address! ')
        if len(password) < 8:
           messages.add_message(request, messages.ERROR, 'Password has to be at least 8 characters! ')
           error="error"
        confirm_password = request.POST['password_confirm']
        if password != confirm_password:
           error="error"
           messages.add_message(request, messages.ERROR, 'Password and Confirm Password do not match! ')
        if len(name) < 4:
           error="error"
           messages.add_message(request, messages.ERROR, 'name has to be at least 4 letters! ')
        else:
           #if str.isalpha(str(request.POST['name'])) == False:
           if not all(c.isalpha() or c.isspace() for c in str(name)):
             error="error"
             messages.add_message(request, messages.ERROR, 'name has to only contain letters and spaces! ')
        if len(request.POST['alias']) < 2:
            error="error"
            messages.add_message(request, messages.ERROR, 'alias has to be at least 2 letters! ')
        else:
           if str.isalpha(str(request.POST['alias'])) == False:
             error="error"
             messages.add_message(request, messages.ERROR, 'alias has to only contain letters! ')
        if error == None:
            if User.objects.filter(email=email).first():
                context = {
                    "category": "register"
                }
                messages.add_message(request, messages.ERROR, 'user exists! Please log in! ')
                return render(request, 'book_review_app/index.html', context)
            passwd_encoded = password.encode('utf-8')
            hashed = bcrypt.hashpw(passwd_encoded, bcrypt.gensalt())
            user = User.objects.create(name=name, alias=alias, password=hashed, email=email)
            print "User objects after create"
            request.session['user_id'] = user.id
            request.session['user_name'] = user.name
            context = {
              "reviews_first3": Review.objects.all().order_by('-created_at')[:3],#User.objects.get(id=user.id)
              "review_others": Review.objects.all().order_by('-created_at')[4:]
            }
            print Review.objects.all()[:3]
            print Review.objects.all()[4:]
            # return redirect("books")
            return render(request, 'book_review_app/books.html', context)
        else:
            context = {
                "category": "register"
            }
            return render(request, 'book_review_app/index.html', context)

def logoff(request):
    try:
        del request.session['user_id']
        del request.session['user_name']
    except KeyError:
        pass
    return redirect('/')

def add(request):
    return render(request, 'book_review_app/add_book_review.html')

def add_book_review(request):
    title=request.POST['title']
    author=request.POST['author']
    review=request.POST['review']
    rating=request.POST['rating']
    u = User.objects.filter(id=request.session['user_id']).first()
    b = Book.objects.create( title=title, author=author, created_at=datetime.now(), updated_at=datetime.now())
    r = Review.objects.create(message=review, user_id=u, book_id=b, rating=rating, created_at=datetime.now(), updated_at=datetime.now())
    print "r="
    print r.user_id.id
    context = {
        "book": b,
        "reviews": Review.objects.filter(book_id=b)
    }
    # return render(request, 'book_review_app/book.html', context)
    return redirect('/lookup_book/'+str(b.id))

def post_review(request, book_id):
    review=request.POST['review']
    rating=request.POST['rating']
    b = Book.objects.get(id=book_id)
    u = User.objects.get(id=request.session['user_id'])
    Review.objects.create(message=review, rating=rating, book_id=b, user_id=u, created_at=datetime.now(), updated_at=datetime.now())
    context = {
        "book": b,
        "reviews": Review.objects.filter(book_id=b)
    }
    return render(request, 'book_review_app/book.html', context)

def user(request, id):
    u = User.objects.get(id=id)
    r = Review.objects.filter(user_id=u)
    count = Review.objects.filter(user_id=u).count()
    books = []
    for i in r:
        book={}
        book['id'] = i.book_id.id
        book['title'] = i.book_id.title
        books.append(book)
    context= {
        "user": u,
        "count": count,
        "books": books
    }
    return render(request, 'book_review_app/user.html', context)

def books(request):
    context = {
      "reviews_first3": Review.objects.all().order_by('-created_at')[:3],#User.objects.get(id=user.id)
      "review_others": Review.objects.all().order_by('-created_at')[4:]
    }
    print Review.objects.all()[:3]
    print Review.objects.all()[4:]
    # u = User.objects.get(id=id)
    # b = Book.objects.filter(author=u)
    # context = {
    #     "login_user_id": u.id,
    #     "book": b,
    #     "reviews": Review.objects.filter(book_id=b)
    # }
    return render(request, 'book_review_app/books.html', context)

def lookup_book(request, id):
    b = Book.objects.filter(id=id).first()
    context = {
        "book": b,
        "reviews": Review.objects.filter(book_id=b)
    }
    print "lookup:"
    print b.title
    return render(request, 'book_review_app/book.html', context)

def delete_review(request, id, book_id):
  print id
  u = User.objects.get(id=request.session['user_id'])
  r = Review.objects.filter(id=id)
  print "delete"
  print len(r)
  b= Book.objects.get(id=book_id)
  r.delete()
  context = {
     "book": b,
     "reviews": Review.objects.filter(book_id=b)
  }
  return render(request, 'book_review_app/book.html', context)
