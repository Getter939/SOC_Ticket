from django.contrib import admin
from django.urls import path, include, re_path
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.dashboard.urls')),          # Dashboard = home
    path('incidents/', include('apps.incidents.urls')),
    path('accounts/', include('apps.accounts.urls')),
    path('wazuh/', include('apps.wazuh_ingest.urls')),
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Uploaded attachments — django.conf.urls.static.static() is a no-op when
# DEBUG=False, but this app has no separate web server fronting MEDIA_ROOT,
# so serve it from Django directly regardless of DEBUG.
urlpatterns += [
    re_path(r'^%s(?P<path>.*)$' % settings.MEDIA_URL.lstrip('/'), serve, {
        'document_root': settings.MEDIA_ROOT,
    }),
]
