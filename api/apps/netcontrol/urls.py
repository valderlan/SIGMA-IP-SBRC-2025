from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import BlacklistViewSet, WhitelistViewSet, AnalysisViewSet, SuspectViewSet


router = DefaultRouter()
router.register(r"blacklist", BlacklistViewSet, basename="blacklist")
router.register(r"whitelist", WhitelistViewSet, basename="whitelist")
router.register(r"pending-analysis", AnalysisViewSet, basename="analysis")
router.register(r"suspect", SuspectViewSet, basename="suspect")


urlpatterns = [
    path("", include(router.urls)),
]
