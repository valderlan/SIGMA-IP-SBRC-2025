from django.urls import path, include
from .views import BlacklistViewSet, WhitelistViewSet, TarpitViewSet
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


urlpatterns = [
    # urls para blacklist
    path('blacklist/list/', BlacklistViewSet.as_view({'get': 'list', 'post': 'create'})),
    path('blacklist/<str:ip_address>/', BlacklistViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'})),

    # urls para whitelist
    path('whitelist/list/', WhitelistViewSet.as_view({'get': 'list', 'post': 'create'})),
    path('whitelist/<str:ip_address>/', WhitelistViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'})),

    # urls para tarpit
    path('tarpit/list/', TarpitViewSet.as_view({'get': 'list', 'post': 'create'})),
    path('tarpit/<str:ip_address>/', TarpitViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'})),

    # SWAGGER
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

]