from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.urls import path, include, re_path
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from apps.accounts import views as account_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.dashboard.urls')),          # Dashboard = home
    path('incidents/', include('apps.incidents.urls')),
    path('accounts/', include('apps.accounts.urls')),
    path('wazuh/', include('apps.wazuh_ingest.urls')),
    # redirect_authenticated_user: without it an already-signed-in visitor gets
    # the login form rendered inside the full app shell (sidebar, nav badges,
    # user pill), which reads as a broken/logged-out state.
    path('login/', auth_views.LoginView.as_view(redirect_authenticated_user=True),
         name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('password-reset/', account_views.ThrottledPasswordResetView.as_view(),
         name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(
         template_name='registration/password_reset_done.html'), name='password_reset_done'),
    path('password-reset/<uidb64>/<token>/', account_views.AccountPasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('password-reset/complete/', auth_views.PasswordResetCompleteView.as_view(
         template_name='registration/password_reset_complete.html'), name='password_reset_complete'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Uploaded attachments are sensitive incident evidence. They are served ONLY
# through the authenticated, authorization-checked download view
# (incidents.views.download_attachment), which verifies the requester may see
# the parent ticket and forces a safe download. We deliberately do NOT expose
# MEDIA_ROOT through an open static route — doing so previously allowed
# unauthenticated downloads and let an uploaded .html/.svg execute as
# same-origin script (stored XSS).
#
# In local development a convenience route is still provided so /media/ links
# resolve, but it is login-gated and forces attachment disposition + nosniff
# so dev mirrors production behaviour.
if settings.DEBUG:
    @login_required
    def _dev_protected_media(request, path):
        response = serve(request, path, document_root=settings.MEDIA_ROOT)
        response['Content-Disposition'] = 'attachment'
        response['X-Content-Type-Options'] = 'nosniff'
        return response

    urlpatterns += [
        re_path(r'^%s(?P<path>.*)$' % settings.MEDIA_URL.lstrip('/'),
                _dev_protected_media),
    ]
