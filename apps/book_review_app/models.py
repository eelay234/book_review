from __future__ import unicode_literals
from django.db import models
import re
from django.http import HttpResponse
from django.contrib import messages

# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=100)
    alias = models.CharField(max_length=45)
    password = models.CharField(max_length=100)
    email = models.EmailField(max_length=75)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    objects = models.Manager()

class Book(models.Model):
    title = models.CharField(max_length=100)
    author= models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    objects = models.Manager()

class Review(models.Model):
    message = models.TextField(max_length=1000)
    user_id = models.ForeignKey(User, related_name="writer")
    book_id = models.ForeignKey(Book, related_name="book_reviewed")
    rating = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    objects = models.Manager()
