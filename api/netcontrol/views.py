from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import filters
from rest_framework import status
from rest_framework.permissions import IsAdminUser
from rest_framework import filters
from django_filters.rest_framework import DjangoFilterBackend
from netcontrol.models import Blacklist, Whitelist, Tarpit
from netcontrol.pagination import GenericPagination
from netcontrol.serializers import (BlacklistSerializer, WhitelistSerializer, TarpitSerializer)
from netcontrol.filters import (BlacklistFilter, WhitelistFilter, TarpitFilter)
from netcontrol.services import ReputacaoService
import time

# view para blacklist
class BlacklistViewSet(viewsets.ModelViewSet):
    queryset = Blacklist.objects.all().order_by('id')
    serializer_class = BlacklistSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ['ip_address', 'country_code', 'city', 'timestamp_added']
    filterset_class = BlacklistFilter
    pagination_class = GenericPagination
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
    lookup_field = "ip_address"


# view para whitelist
class WhitelistViewSet(viewsets.ModelViewSet):
    queryset = Whitelist.objects.all().order_by('id')
    serializer_class = WhitelistSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ['ip_address', 'timestamp_added']
    filterset_class = WhitelistFilter
    pagination_class = GenericPagination
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
    lookup_field = "ip_address"


# view para tarpit
class TarpitViewSet(viewsets.ModelViewSet):
    queryset = Tarpit.objects.all().order_by('id')
    serializer_class = TarpitSerializer
    lookup_field = 'ip_address'
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, DjangoFilterBackend]
    search_fields = ['ip_address', 'country_code', 'abuse_confidence_score']
    filterset_class = TarpitFilter
    pagination_class = GenericPagination
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
    lookup_field = "ip_address"

    def create(self, request, *args, **kwargs):
        # Começa temporizador
        start_time = time.time()

        # cria o objeto na Tarpit 
        super().create(request, *args, **kwargs)

        ip_address = request.data.get('ip_address')  # obtém o IP enviado
        print(f"IP recebido: {ip_address}")

        # chama o serviço de reputação
        response = ReputacaoService.filtrar_tarpit(ip_address)

        if not response or "status" not in response:
            print("Erro: Resposta inválida ou sem status")
            return Response({"detail": "Erro ao processar reputação do IP"}, status=500)

        print(f"Status retornado: {response['status']}")

        # Calcula o tempo de execução. Espera o resultado da requisição p/ contabilizar.
        execution_time = (time.time() - start_time) * 1000
        print(f"Tempo de tratar a requisição na API: {execution_time:.3f} milisegundos")

        # retorna a reputação (black ou white) e o status
        return Response(response, status=201)