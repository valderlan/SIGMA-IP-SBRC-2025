import logging
import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

# Configuração básica de diretórios se rodado isoladamente
if __name__ == "__main__":
    sys.path.append(os.getcwd())

def setup_logger(log_dir="logs", log_name="outlier_cleaning.log"):
    """
    Configura o logger para salvar em arquivo e também exibir no console.
    """
    # Criar pasta de logs se não existir
    os.makedirs(log_dir, exist_ok=True)
    
    log_path = os.path.join(log_dir, log_name)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # Evita múltiplos handlers quando o script é executado várias vezes
    if logger.hasHandlers():
        logger.handlers.clear()

    # Formato do log
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Handler para console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Handler para arquivo
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info(f"Log ativo. Salvando em: {log_path}")

    return logger


def remove_outliers_isolation_forest(
    input_file="datasets/dataset_ip_normm.csv",
    output_file="datasets/dataset_ip_cleaned.csv",
    contamination=0.05,
    random_state=42
):
    """
    Remove outliers do dataset usando Isolation Forest e mostra a distribuição final.
    """

    logger = logging.getLogger(__name__)  # Usa o logger já configurado

    if not os.path.exists(input_file):
        logger.error(f"Arquivo de entrada não encontrado: {input_file}")
        return None

    logger.info("=" * 60)
    logger.info("INICIANDO REMOÇÃO DE OUTLIERS (ISOLATION FOREST)")
    logger.info("=" * 60)

    try:
        # 1. Carregar Dataset
        df = pd.read_csv(input_file)
        initial_rows = len(df)
        logger.info(f"Dataset carregado: {initial_rows} linhas")

        # 2. Selecionar colunas numéricas para análise (exclui metadados)
        cols_to_ignore = ['ip', 'classification', 'ground_truth', 'prediction_match', 'confidence_score']
        feature_cols = [col for col in df.columns if col not in cols_to_ignore]

        # Garantir somente números
        X = df[feature_cols].select_dtypes(include=[np.number])

        logger.info(f"Features utilizadas para detecção: {list(X.columns)}")

        # 3. Aplicar Isolation Forest
        logger.info(f"Configurando Isolation Forest com contaminação={contamination}")
        iso_forest = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )

        # Predição: 1 = normal, -1 = outlier
        preds = iso_forest.fit_predict(X)

        # 4. Filtrar Dataset
        mask_inliers = preds == 1
        df_cleaned = df[mask_inliers]
        df_outliers = df[~mask_inliers]

        removed_count = len(df_outliers)
        final_rows = len(df_cleaned)

        # 5. Análise dos Outliers Removidos
        if 'classification' in df.columns:
            logger.info("-" * 30)
            logger.info("Distribuição de classes removidas (Outliers):")
            outlier_counts = df_outliers['classification'].value_counts().to_dict()
            logger.info(f"{outlier_counts}")

        # 6. Salvar dataset limpo
        df_cleaned.to_csv(output_file, index=False)

        # --- RELATÓRIO FINAL ---
        logger.info("-" * 30)
        logger.info(f"Linhas iniciais: {initial_rows}")
        logger.info(f"Linhas removidas: {removed_count} ({removed_count/initial_rows:.1%})")
        logger.info(f"Linhas finais:    {final_rows}")

        if 'classification' in df_cleaned.columns:
            logger.info("-" * 30)
            logger.info("DISTRIBUIÇÃO FINAL DE CLASSES (Dataset Limpo):")
            final_counts = df_cleaned['classification'].value_counts()

            for class_name, count in final_counts.items():
                percent = (count / final_rows) * 100
                logger.info(f"  {class_name:<12}: {count} ({percent:.1f}%)")

        logger.info("-" * 30)
        logger.info(f"Dataset limpo salvo em: {output_file}")

        return df_cleaned

    except Exception as e:
        logger.error(f"Erro na remoção de outliers: {e}")
        return None


if __name__ == "__main__":
    logger = setup_logger(log_dir="logs", log_name="outlier_cleaning.log")

    # Caminhos de entrada/saída
    input_csv = "datasets/dataset_ip_normX.csv"
    output_csv = "datasets/dataset_ip_norm.csv"

    # Contaminação de 2%
    remove_outliers_isolation_forest(
        input_file=input_csv,
        output_file=output_csv,
        contamination=0.02
    )
