from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^breached$',views.breached),
    url(r'^logorreg$', views.logorreg),
    url(r'^register$', views.register),
    url(r'^welcome$', views.welcome),
    url(r'^login$', views.login),
    url(r'^logout$', views.logout),
    url(r'^post$', views.post),
    url(r'^delpost$', views.delpost),
    url(r'^comment$',views.comment),
    url(r'^delcom$',views.delcom)

]