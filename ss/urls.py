from django.conf.urls import patterns, include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
 
# Uncomment the next two lines to enable the admin:
#from django.contrib import admin
#admin.autodiscover()
 
urlpatterns = patterns('',
    url(r'^$', 'ss.views.index', name='index'),

    # RLJ just for testing
    # Link the view ss.views.upload to URL recover/upload.html
    #url(r'^upload.html$', 'ss.views.post_upload', name='post_upload'),
 
    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
 
    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),

    # Password Change (when user knows passowrd)
    url(r'^change_password.html$', 'ss.views.change_password', name='change_password'),
    
    # Password Recovery
    url(r'^recover.html$', 'ss.views.send_recovery_email', name='send_recovery_email'),
    url(r'^(?P<token>.*)/$', 'ss.views.reset_password', name='reset_password'),
)

urlpatterns += staticfiles_urlpatterns()
