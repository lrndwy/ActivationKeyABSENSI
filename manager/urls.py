from django.urls import path

from manager.views import (ActivateKeyView, CreateEncryptionKeyView,
                           EncryptionKeyListView, activate_page,
                           login_view, logout_view, delete_key)

urlpatterns = [
    path('', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('key_list/', EncryptionKeyListView.as_view(), name='key_list'),
    path('create/', CreateEncryptionKeyView.as_view(), name='create_key'),
    path('activate/', ActivateKeyView.as_view(), name='activate_key'),
    path('activate-page/', activate_page, name='activate_page'),
    path('delete_key/<int:key_id>/', delete_key, name='delete_key'),
]
