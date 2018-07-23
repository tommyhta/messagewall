from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^register$', views.register),
    url(r'^login$', views.login),
    url(r'^welcome$', views.welcome),
    url(r'^logout$', views.logout),
    url(r'^breached$', views.breached),
# ---------------------------------------- basic register, login and out, rendering registration page and home page   
    url(r'^admin$', views.admin),
    url(r'^changetype$',views.changetype),
    url(r'^deleteuser$', views.deleteuser),
# ---------------------------------------- rendering admin page and admin functions
    url(r'^user/(?P<id>\d+)$', views.user, name="user")
]