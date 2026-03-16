from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAdminUser
from django_filters.rest_framework import DjangoFilterBackend
from apps.netcontrol.models import Blacklist, Whitelist, Analysis, Suspect
from apps.netcontrol.pagination import GenericPagination
from apps.netcontrol.serializers import (
    BlacklistSerializer,
    WhitelistSerializer,
    AnalysisSerializer,
    SuspectSerializer,
)
from apps.netcontrol.filters import (
    BlacklistFilter,
    WhitelistFilter,
    AnalysisFilter,
    SuspectFilter,
)
from apps.netcontrol.services.ip_classification import IpClassificationService
from drf_spectacular.utils import extend_schema_view, extend_schema
from utils.time import write_timing_csv
import time
import logging

logger = logging.getLogger(__name__)


@extend_schema_view(
    create=extend_schema(
        summary="Creates a blacklist object",
        description="Creates a new blacklist object.",
        tags=["denylist"]
    ),
    list=extend_schema(
        summary="List all blacklist objects",
        description="Returns a list of all blacklist objects.",
        tags=["denylist"]
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific blacklist object",
        description="Returns a blacklist object by its IP.",
        tags=["denylist"]
    ),
    update=extend_schema(
        summary="Update a blacklist object",
        description="Updates an blacklist object by its IP.",
        tags=["denylist"]
    ),
    partial_update=extend_schema(
        summary="Partially update an blacklist object",
        description="Partially updates a blacklist object by its IP.",
        tags=["denylist"]
    ),
    destroy=extend_schema(
        summary="Delete a blacklist object",
        description="Deletes a blacklist object by its IP",
        tags=["denylist"]
    ),
)
class BlacklistViewSet(viewsets.ModelViewSet):
    queryset = Blacklist.objects.all().order_by("-id")
    serializer_class = BlacklistSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "country_code", "city", "timestamp_added"]
    filterset_class = BlacklistFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"


@extend_schema_view(
    create=extend_schema(
        summary="Creates a whitelist object",
        description="Creates a new whitelist object.",
        tags=["allowlist"]
    ),
    list=extend_schema(
        summary="List all whitelist objects",
        description="Returns a list of all whitelist objects.",
        tags=["allowlist"]
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific whitelist object",
        description="Returns a whitelist object by its IP.",
        tags=["allowlist"]
    ),
    update=extend_schema(
        summary="Update a whitelist object",
        description="Updates an whitelist object by its IP.",
        tags=["allowlist"]
    ),
    partial_update=extend_schema(
        summary="Partially update an whitelist object",
        description="Partially updates a whitelist object by its IP.",
        tags=["allowlist"]
    ),
    destroy=extend_schema(
        summary="Delete a whitelist object",
        description="Deletes a whitelist object by its IP",
        tags=["allowlist"]
    ),
)
class WhitelistViewSet(viewsets.ModelViewSet):
    queryset = Whitelist.objects.all().order_by("id")
    serializer_class = WhitelistSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "timestamp_added"]
    filterset_class = WhitelistFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"


@extend_schema_view(
    create=extend_schema(
        summary="Creates a analysis object",
        description="Creates a new analysis object.",
        tags=["analysis"]
    ),
    list=extend_schema(
        summary="List all analysis objects",
        description="Returns a list of all analysis objects.",
        tags=["analysis"]
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific analysis object",
        description="Returns a analysis object by its IP.",
        tags=["analysis"]
    ),
    update=extend_schema(
        summary="Update a analysis object",
        description="Updates an analysis object by its IP.",
        tags=["analysis"]
    ),
    partial_update=extend_schema(
        summary="Partially update an analysis object",
        description="Partially updates a analysis object by its IP.",
        tags=["analysis"]
    ),
    destroy=extend_schema(
        summary="Delete a analysis object",
        description="Deletes a analysis object by its IP",
        tags=["analysis"]
    ),
)
class AnalysisViewSet(viewsets.ModelViewSet):
    queryset = Analysis.objects.all().order_by("-id")
    serializer_class = AnalysisSerializer
    lookup_field = "ip_address"
    permission_classes = [IsAdminUser]
    filter_backends = [SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "country_code", "abuseipdb_confidence_score"]
    filterset_class = AnalysisFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"

    def create(self, request, *args, **kwargs):
        start_time = time.perf_counter()

        super().create(request, *args, **kwargs)

        ip_address = request.data.get("ip_address")
        logger.info(f"\nIP recebido: {ip_address}")

        data = IpClassificationService.filter_and_classify_ip(ip_address)

        total_api = (time.perf_counter() - start_time) * 1000

        timings = data.pop("_timings", {})
        timings["total_api"] = round(total_api, 3)

        write_timing_csv(ip_address, timings)

        if not data or "verdict" not in data:
            logger.error("Erro: Resposta inválida ou sem veredito")
            return Response(
                {"detail": "Erro ao processar reputação do IP"},
                status=500,
            )

        logger.info(f"Veredito retornado: {data['verdict']}")

        logger.info(
            f"Tempo total da requisição HTTP: {total_api:.3f} ms"
        )

        return Response(data, status=201)


@extend_schema_view(
    create=extend_schema(
        summary="Creates a suspect object",
        description="Creates a new suspect object.",
        tags=["suspicious"]
    ),
    list=extend_schema(
        summary="List all suspect objects",
        description="Returns a list of all suspect objects.",
        tags=["suspicious"]
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific suspect object",
        description="Returns a suspect object by its IP.",
        tags=["suspicious"]
    ),
    update=extend_schema(
        summary="Update a suspect object",
        description="Updates an suspect object by its IP.",
        tags=["suspicious"]
    ),
    partial_update=extend_schema(
        summary="Partially update an suspect object",
        description="Partially updates a suspect object by its IP.",
        tags=["suspicious"]
    ),
    destroy=extend_schema(
        summary="Delete a suspect object",
        description="Deletes a suuspect object by its IP",
        tags=["suspicious"]
    ),
)
class SuspectViewSet(viewsets.ModelViewSet):
    queryset = Suspect.objects.all().order_by("-id")
    serializer_class = SuspectSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "timestamp_added"]
    filterset_class = SuspectFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"
