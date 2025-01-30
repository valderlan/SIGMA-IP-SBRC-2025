import json
import os
import shutil
from datetime import datetime

import pandas as pd


def create_experiment_directory():

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    data_dir = os.path.join(base_dir, "data")
    images_dir = os.path.join(data_dir, "images")
    models_dir = os.path.join(data_dir, "models")
    experiments_dir = os.path.join(data_dir, "experiments")

    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(images_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(experiments_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    experiment_dir = os.path.join(experiments_dir, f"experiment_{timestamp}")
    experiment_images = os.path.join(experiment_dir, "images")
    experiment_models = os.path.join(experiment_dir, "models")

    os.makedirs(experiment_dir, exist_ok=True)
    os.makedirs(experiment_images, exist_ok=True)
    os.makedirs(experiment_models, exist_ok=True)

    print(f"\nEstrutura de diretórios criada:")
    print(f"- Diretório de dados: {data_dir}")
    print(f"- Imagens principais: {images_dir}")
    print(f"- Modelos principais: {models_dir}")
    print(f"- Experimento atual: {experiment_dir}")

    return experiment_dir


def save_experiment_config(config_dict, experiment_dir):

    config_path = os.path.join(experiment_dir, "experiment_config.json")
    with open(config_path, "w") as f:
        json.dump(config_dict, f, indent=4)
    print(f"Configuração salva em: {config_path}")


def log_execution_info(message, experiment_dir, print_msg=True):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}\n"

    log_path = os.path.join(experiment_dir, "execution.log")
    with open(log_path, "a") as f:
        f.write(log_message)

    if print_msg:
        print(message)


def generate_summary_report(metrics_df, accuracy_df, execution_times, experiment_dir):

    report = []
    report.append("# Relatório de Execução do Modelo\n")
    report.append(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    report.append("\n## Métricas de Performance\n")
    report.append(metrics_df.to_markdown())

    report.append("\n## Acurácia por Modelo\n")
    report.append(accuracy_df.to_markdown())

    report.append("\n## Tempos de Execução\n")
    exec_df = pd.DataFrame.from_dict(
        execution_times, orient="index", columns=["Tempo (s)"]
    )
    report.append(exec_df.to_markdown())

    report_path = os.path.join(experiment_dir, "summary_report.md")
    with open(report_path, "w") as f:
        f.write("\n".join(report))

    print(f"Relatório gerado em: {report_path}")
    return report_path


def copy_to_main_directories(file_path, data_dir, file_type):

    if not os.path.exists(file_path):
        print(f"Arquivo não encontrado: {file_path}")
        return

    filename = os.path.basename(file_path)
    if file_type == "image":
        dest_dir = os.path.join(data_dir, "images")
    else:
        dest_dir = os.path.join(data_dir, "models")

    dest_path = os.path.join(dest_dir, filename)
    shutil.copy2(file_path, dest_path)
    print(f"Arquivo copiado para: {dest_path}")
