from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import filters
from rest_framework.permissions import IsAdminUser
from django_filters.rest_framework import DjangoFilterBackend
from apps.netcontrol.models import Blacklist, Whitelist, Tarpit, Suspect
from apps.netcontrol.pagination import GenericPagination
from apps.netcontrol.serializers import (
    BlacklistSerializer,
    WhitelistSerializer,
    TarpitSerializer,
    SuspectSerializer,
)
from apps.netcontrol.filters import (
    BlacklistFilter,
    WhitelistFilter,
    TarpitFilter,
    SuspectFilter,
)
from apps.netcontrol.services import filtrar_tarpit
from drf_spectacular.utils import extend_schema_view, extend_schema
import time
import logging

logger = logging.getLogger(__name__)


@extend_schema_view(
    create=extend_schema(
        summary="Creates a blacklist object",
        description="Creates a new blacklist object.",
    ),
    list=extend_schema(
        summary="List all blacklist objects",
        description="Returns a list of all blacklist objects.",
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific blacklist object",
        description="Returns a blacklist object by its IP.",
    ),
    update=extend_schema(
        summary="Update a blacklist object",
        description="Updates an blacklist object by its IP.",
    ),
    partial_update=extend_schema(
        summary="Partially update an blacklist object",
        description="Partially updates a blacklist object by its IP.",
    ),
    destroy=extend_schema(
        summary="Delete a blacklist object",
        description="Deletes a blacklist object by its IP",
    ),
)
class BlacklistViewSet(viewsets.ModelViewSet):
    queryset = Blacklist.objects.all().order_by("id")
    serializer_class = BlacklistSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "country_code", "city", "timestamp_added"]
    filterset_class = BlacklistFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"


@extend_schema_view(
    create=extend_schema(
        summary="Creates a whitelist object",
        description="Creates a new whitelist object.",
    ),
    list=extend_schema(
        summary="List all whitelist objects",
        description="Returns a list of all whitelist objects.",
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific whitelist object",
        description="Returns a whitelist object by its IP.",
    ),
    update=extend_schema(
        summary="Update a whitelist object",
        description="Updates an whitelist object by its IP.",
    ),
    partial_update=extend_schema(
        summary="Partially update an whitelist object",
        description="Partially updates a whitelist object by its IP.",
    ),
    destroy=extend_schema(
        summary="Delete a whitelist object",
        description="Deletes a whitelist object by its IP",
    ),
)
class WhitelistViewSet(viewsets.ModelViewSet):
    queryset = Whitelist.objects.all().order_by("id")
    serializer_class = WhitelistSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "timestamp_added"]
    filterset_class = WhitelistFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"


@extend_schema_view(
    create=extend_schema(
        summary="Creates a tarpit object",
        description="Creates a new tarpit object.",
    ),
    list=extend_schema(
        summary="List all tarpit objects",
        description="Returns a list of all tarpit objects.",
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific tarpit object",
        description="Returns a tarpit object by its IP.",
    ),
    update=extend_schema(
        summary="Update a tarpit object",
        description="Updates an tarpit object by its IP.",
    ),
    partial_update=extend_schema(
        summary="Partially update an tarpit object",
        description="Partially updates a tarpit object by its IP.",
    ),
    destroy=extend_schema(
        summary="Delete a tarpit object",
        description="Deletes a tarpit object by its IP",
    ),
)
class TarpitViewSet(viewsets.ModelViewSet):
    queryset = Tarpit.objects.all().order_by("id")
    serializer_class = TarpitSerializer
    lookup_field = "ip_address"
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "country_code", "abuseipdb_confidence_score"]
    filterset_class = TarpitFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"

    def create(self, request, *args, **kwargs):
        # Começa temporizador
        start_time = time.time()

        super().create(request, *args, **kwargs)

        ip_address = request.data.get("ip_address")  # obtém o IP enviado
        logger.info(f"\nIP recebido: {ip_address}")

        # Chama o serviço de reputação
        data = filtrar_tarpit(ip_address)

        if not data or "status" not in data:
            logger.error("Erro: Resposta inválida ou sem status")
            return Response({"detail": "Erro ao processar reputação do IP"}, status=500)

        logger.info(f"Status retornado: {data['status']}")

        # Calcula o tempo de execução. Espera o resultado da requisição p/ contabilizar.
        execution_time = (time.time() - start_time) * 1000
        logger.info(
            f"Tempo de tratar a requisição na API: {execution_time:.3f} milisegundos"
        )

        # Retorna a reputação e o status
        return Response(data, status=201)


@extend_schema_view(
    create=extend_schema(
        summary="Creates a suspect object",
        description="Creates a new suspect object.",
    ),
    list=extend_schema(
        summary="List all suspect objects",
        description="Returns a list of all suspect objects.",
    ),
    retrieve=extend_schema(
        summary="Retrieve a specific suspect object",
        description="Returns a suspect object by its IP.",
    ),
    update=extend_schema(
        summary="Update a suspect object",
        description="Updates an suspect object by its IP.",
    ),
    partial_update=extend_schema(
        summary="Partially update an suspect object",
        description="Partially updates a suspect object by its IP.",
    ),
    destroy=extend_schema(
        summary="Delete a suspect object",
        description="Deletes a suuspect object by its IP",
    ),
)
class SuspectViewSet(viewsets.ModelViewSet):
    queryset = Suspect.objects.all().order_by("id")
    serializer_class = SuspectSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ["ip_address", "timestamp_added"]
    filterset_class = SuspectFilter
    pagination_class = GenericPagination
    http_method_names = ["get", "post", "put", "patch", "delete"]
    lookup_field = "ip_address"
