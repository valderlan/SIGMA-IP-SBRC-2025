import json
import os
import shutil
from datetime import datetime
from pathlib import Path

import pandas as pd


def create_experiment_directory():
    """
    Cria estrutura de diretórios para experimento com verificação robusta.
    Garante que os diretórios sejam criados e sejam visíveis.
    """
    # Obter diretório base de forma mais robusta
    if __file__:
        # Se executando como script
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    else:
        # Se executando interativamente
        base_dir = os.getcwd()
    
    # Forçar uso do diretório atual se necessário
    if not os.access(base_dir, os.W_OK):
        base_dir = os.getcwd()
        print(f"⚠️  Usando diretório atual devido a permissões: {base_dir}")

    # Criar estrutura de diretórios
    data_dir = os.path.join(base_dir, "data")
    images_dir = os.path.join(data_dir, "images")
    models_dir = os.path.join(data_dir, "models")
    experiments_dir = os.path.join(data_dir, "experiments")

    # Criar diretórios com verificação
    dirs_to_create = [data_dir, images_dir, models_dir, experiments_dir]
    
    for directory in dirs_to_create:
        try:
            os.makedirs(directory, exist_ok=True)
            # Verificar se foi criado
            if not os.path.exists(directory):
                raise Exception(f"Diretório não foi criado: {directory}")
            print(f"✅ Diretório criado/verificado: {directory}")
        except Exception as e:
            print(f"❌ Erro ao criar diretório {directory}: {e}")
            # Tentar criar no diretório atual como fallback
            fallback_dir = os.path.join(os.getcwd(), os.path.basename(directory))
            os.makedirs(fallback_dir, exist_ok=True)
            print(f"🔄 Usando fallback: {fallback_dir}")

    # Criar diretório específico do experimento
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_dir = os.path.join(experiments_dir, f"experiment_{timestamp}")
    experiment_images = os.path.join(experiment_dir, "images")
    experiment_models = os.path.join(experiment_dir, "models")

    # Criar diretórios do experimento
    experiment_dirs = [experiment_dir, experiment_images, experiment_models]
    
    for directory in experiment_dirs:
        try:
            os.makedirs(directory, exist_ok=True)
            if not os.path.exists(directory):
                raise Exception(f"Diretório do experimento não foi criado: {directory}")
        except Exception as e:
            print(f"❌ Erro ao criar {directory}: {e}")
            # Criar no diretório atual como último recurso
            fallback_path = os.path.join(os.getcwd(), f"experiment_{timestamp}")
            os.makedirs(fallback_path, exist_ok=True)
            fallback_images = os.path.join(fallback_path, "images")
            fallback_models = os.path.join(fallback_path, "models")
            os.makedirs(fallback_images, exist_ok=True)
            os.makedirs(fallback_models, exist_ok=True)
            
            print(f"🔄 Usando diretório atual: {fallback_path}")
            return fallback_path

    print(f"\n📁 Estrutura de diretórios criada com sucesso:")
    print(f"- Diretório de dados: {data_dir}")
    print(f"- Imagens principais: {images_dir}")
    print(f"- Modelos principais: {models_dir}")
    print(f"- Experimento atual: {experiment_dir}")
    
    # Verificação final
    if not os.path.exists(experiment_dir):
        raise Exception(f"FALHA CRÍTICA: Diretório de experimento não existe: {experiment_dir}")
    
    # Teste de escrita
    try:
        test_file = os.path.join(experiment_dir, "test_write.txt")
        with open(test_file, 'w') as f:
            f.write("teste de escrita")
        os.remove(test_file)
        print(f"✅ Teste de escrita bem-sucedido em: {experiment_dir}")
    except Exception as e:
        print(f"❌ ERRO: Não é possível escrever em: {experiment_dir}")
        print(f"   Erro: {e}")
        raise

    return experiment_dir


def save_experiment_config(config_dict, experiment_dir):
    """
    Salva configuração do experimento com verificação.
    """
    try:
        config_path = os.path.join(experiment_dir, "experiment_config.json")
        
        # Verificar se diretório existe
        if not os.path.exists(experiment_dir):
            os.makedirs(experiment_dir, exist_ok=True)
        
        # Salvar configuração
        with open(config_path, "w", encoding='utf-8') as f:
            json.dump(config_dict, f, indent=4, ensure_ascii=False)
        
        # Verificar se foi salvo
        if os.path.exists(config_path):
            print(f"✅ Configuração salva em: {config_path}")
        else:
            raise Exception("Arquivo de configuração não foi criado")
            
    except Exception as e:
        print(f"❌ Erro ao salvar configuração: {e}")
        # Tentar salvar no diretório atual
        fallback_path = os.path.join(os.getcwd(), "experiment_config.json")
        try:
            with open(fallback_path, "w", encoding='utf-8') as f:
                json.dump(config_dict, f, indent=4, ensure_ascii=False)
            print(f"🔄 Configuração salva em fallback: {fallback_path}")
        except:
            print(f"❌ Falha total ao salvar configuração")


def log_execution_info(message, experiment_dir, print_msg=True):
    """
    Log de execução com fallback robusto.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}\n"

    if print_msg:
        print(message)

    # Tentar salvar no diretório do experimento
    try:
        if not os.path.exists(experiment_dir):
            os.makedirs(experiment_dir, exist_ok=True)
            
        log_path = os.path.join(experiment_dir, "execution.log")
        with open(log_path, "a", encoding='utf-8') as f:
            f.write(log_message)
    except Exception as e:
        # Fallback para diretório atual
        try:
            log_path = os.path.join(os.getcwd(), "execution.log")
            with open(log_path, "a", encoding='utf-8') as f:
                f.write(f"[FALLBACK] {log_message}")
        except:
            pass  # Se não conseguir logar, apenas continue


def generate_summary_report(metrics_df, accuracy_df, execution_times, results_df, experiment_dir):
    """
    Gera relatório resumo com verificação de salvamento.
    """
    try:
        report = []
        report.append("# Relatório de Execução do Modelo\n")
        report.append(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        report.append("\n## Hiperparâmetros Otimizados por Modelo\n")
        for model_name, row in results_df.iterrows():
            hyperparams = row.get("Melhores Parâmetros", "N/A")
            report.append(f"- **{model_name}**: {hyperparams}")

        report.append("\n## Métricas de Performance\n")
        report.append(metrics_df.to_markdown())

        report.append("\n## Acurácia por Modelo\n")
        report.append(accuracy_df.to_markdown())

        report.append("\n## Tempos de Execução\n")
        exec_df = pd.DataFrame.from_dict(
            execution_times, orient="index", columns=["Tempo (s)"]
        )
        report.append(exec_df.to_markdown())

        # Tentar salvar no diretório do experimento
        report_content = "\n".join(report)
        
        try:
            if not os.path.exists(experiment_dir):
                os.makedirs(experiment_dir, exist_ok=True)
                
            report_path = os.path.join(experiment_dir, "summary_report.md")
            with open(report_path, "w", encoding='utf-8') as f:
                f.write(report_content)
                
            # Verificar se foi salvo
            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                print(f"✅ Relatório gerado em: {report_path}")
                return report_path
            else:
                raise Exception("Relatório não foi salvo corretamente")
                
        except Exception as e:
            print(f"❌ Erro ao salvar relatório: {e}")
            # Fallback para diretório atual
            fallback_path = os.path.join(os.getcwd(), f"summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
            with open(fallback_path, "w", encoding='utf-8') as f:
                f.write(report_content)
            print(f"🔄 Relatório salvo em fallback: {fallback_path}")
            return fallback_path
            
    except Exception as e:
        print(f"❌ Erro crítico ao gerar relatório: {e}")
        return None


def copy_to_main_directories(file_path, data_dir, file_type):
    """
    Copia arquivos para diretórios principais com verificação.
    """
    if not os.path.exists(file_path):
        print(f"❌ Arquivo não encontrado: {file_path}")
        return

    try:
        filename = os.path.basename(file_path)
        if file_type == "image":
            dest_dir = os.path.join(data_dir, "images")
        else:
            dest_dir = os.path.join(data_dir, "models")

        # Criar diretório de destino se não existir
        os.makedirs(dest_dir, exist_ok=True)
        
        dest_path = os.path.join(dest_dir, filename)
        shutil.copy2(file_path, dest_path)
        
        # Verificar se foi copiado
        if os.path.exists(dest_path):
            print(f"✅ Arquivo copiado para: {dest_path}")
        else:
            print(f"❌ Falha na cópia para: {dest_path}")
            
    except Exception as e:
        print(f"❌ Erro ao copiar arquivo: {e}")


def verify_and_list_outputs(experiment_dir):
    """
    Verifica e lista todos os arquivos gerados no experimento.
    """
    print(f"\n📋 VERIFICANDO ARQUIVOS GERADOS...")
    print(f"📁 Diretório: {experiment_dir}")
    
    if not os.path.exists(experiment_dir):
        print(f"❌ Diretório não existe: {experiment_dir}")
        return
    
    # Listar todos os arquivos recursivamente
    all_files = []
    for root, dirs, files in os.walk(experiment_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            rel_path = os.path.relpath(file_path, experiment_dir)
            all_files.append((rel_path, file_size))
    
    if all_files:
        print(f"✅ {len(all_files)} arquivos encontrados:")
        for rel_path, size in sorted(all_files):
            size_str = f"{size:,} bytes" if size < 1024 else f"{size/1024:.1f} KB"
            print(f"  📄 {rel_path} ({size_str})")
    else:
        print(f"❌ Nenhum arquivo encontrado em: {experiment_dir}")
    
    return all_files