from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^lookup_book/(\d+)/$', views.lookup_book),
    url(r'^delete_review/(\d+)/(\d+)/$', views.delete_review),
    url(r'^books/$', views.books),
    url(r'^users/(\d+)/$', views.user),
    url(r'^post_review/(\d+)/$', views.post_review),
    url(r'^books/add_book_review/$', views.add_book_review),
    url(r'^books/add/$', views.add),
    url(r'^registration$', views.registration),
    # url(r'^register$', views.register),
    url(r'^logoff$', views.logoff),
    url(r'^login$', views.login),
    url(r'^$', views.index)
]
