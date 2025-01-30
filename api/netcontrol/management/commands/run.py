from django.core.management.base import BaseCommand
from netcontrol.services import RedeLocalService

class Command(BaseCommand):
    help = 'Atualiza as listas de Blacklist e Whitelist e filtra entradas da Tarpit'

    def handle(self, *args, **kwargs):
        # Executa o serviço para obter e adicionar o IP próprio na whitelist, se necessário
        network = input('Digite sua faixa: ') # Insira sua faixa para scan, exemplo: '10.129.4.0/24'

        RedeLocalService.scan_network(network)
