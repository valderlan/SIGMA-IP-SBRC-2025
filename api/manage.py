import os
import sys
import signal
import django

def delete_tarpit_objects(signal, frame):
    """
    Função para deletar todos os objetos da tabela Tarpit
    ao pressionar Ctrl + C.
    """
    print("\nEncerrando servidor... Limpando tabela Tarpit.")
    try:
        from django.db import connections
        from netcontrol.models import Tarpit
        django.setup()  # Garante que o ambiente Django esteja configurado
        Tarpit.objects.all().delete()
        print("Todos os objetos na tabela Tarpit foram deletados.")
    except Exception as e:
        print(f"Erro ao deletar objetos da tabela Tarpit: {e}")
    finally:
        sys.exit(0)

if __name__ == "__main__":
    # Configura o sinal SIGINT (Ctrl + C) para chamar delete_tarpit_objects
    signal.signal(signal.SIGINT, delete_tarpit_objects)

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api_settings.settings')  

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Não foi possível importar o Django. Você tem certeza que está instalado e "
            "disponível em sua variável de ambiente PYTHONPATH ? Você "
            "esqueceu de ativar o ambiente virtual?"
        ) from exc
    execute_from_command_line(sys.argv)
