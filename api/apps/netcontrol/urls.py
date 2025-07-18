from django.urls import path
from .views import BlacklistViewSet, WhitelistViewSet, TarpitViewSet, SuspectViewSet


urlpatterns = [
    # urls para blacklist
    path("blacklist/", BlacklistViewSet.as_view({"get": "list", "post": "create"})),
    path(
        "blacklist/<str:ip_address>/",
        BlacklistViewSet.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
                "delete": "destroy",
            }
        ),
    ),
    # urls para whitelist
    path("whitelist/", WhitelistViewSet.as_view({"get": "list", "post": "create"})),
    path(
        "whitelist/<str:ip_address>/",
        WhitelistViewSet.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
                "delete": "destroy",
            }
        ),
    ),
    # urls para tarpit
    path("tarpit/", TarpitViewSet.as_view({"get": "list", "post": "create"})),
    path(
        "tarpit/<str:ip_address>/",
        TarpitViewSet.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
                "delete": "destroy",
            }
        ),
    ),
    # urls para suspect
    path("suspect/", SuspectViewSet.as_view({"get": "list", "post": "create"})),
    path(
        "suspect/<str:ip_address>/",
        SuspectViewSet.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
                "delete": "destroy",
            }
        ),
    ),
]
