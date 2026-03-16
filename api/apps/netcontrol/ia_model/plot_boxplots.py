import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
import logging
import math

# Configuração para rodar isoladamente
if __name__ == "__main__":
    sys.path.append(os.getcwd())

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    return logging.getLogger(__name__)

def plot_cleaned_boxplots(
    input_file="datasets/dataset_ip_norm.csv",
    output_image="datasets/boxplot_cleaned_data.png"
):
    """
    Gera boxplots para todas as colunas numéricas do dataset limpo.
    """
    logger = logging.getLogger(__name__)
    
    if not os.path.exists(input_file):
        logger.error(f"Arquivo não encontrado: {input_file}")
        logger.warning("Execute o script 'remove_outliers.py' antes de tentar gerar os gráficos.")
        return

    try:
        logger.info(f"Carregando dataset para plotagem: {input_file}")
        df = pd.read_csv(input_file)
        
        # Filtrar apenas colunas numéricas relevantes (ignorando metadados)
        cols_to_ignore = ['ip', 'classification', 'ground_truth', 'prediction_match', 'confidence_score']
        numeric_cols = [c for c in df.columns if c not in cols_to_ignore and pd.api.types.is_numeric_dtype(df[c])]
        
        num_features = len(numeric_cols)
        if num_features == 0:
            logger.warning("Nenhuma coluna numérica encontrada para plotar.")
            return

        logger.info(f"Gerando boxplots para {num_features} features...")

        # Configuração do Grid (Layout dinâmico)
        n_cols = 3
        n_rows = math.ceil(num_features / n_cols)
        
        # Tamanho da figura baseado no número de linhas (Altura dinâmica)
        plt.figure(figsize=(15, 4 * n_rows))
        
        # Estilo visual
        sns.set_theme(style="whitegrid")
        
        for i, col in enumerate(numeric_cols, 1):
            plt.subplot(n_rows, n_cols, i)
            
            # Plot do Boxplot vertical
            sns.boxplot(y=df[col], color='#4c72b0', width=0.5, flierprops={"marker": "x"})
            
            plt.title(col, fontsize=10, fontweight='bold')
            plt.ylabel('Valor Normalizado')
            
        plt.suptitle(f'Distribuição das Features (Pós-Remoção de Outliers)\nN={len(df)} registros', fontsize=16, y=1.02)
        plt.tight_layout()
        
        # Salvar a imagem
        plt.savefig(output_image, bbox_inches='tight', dpi=300)
        logger.info(f"Gráfico salvo com sucesso em: {output_image}")
        
        # Tenta exibir se houver interface gráfica disponível
        try:
            plt.show()
        except Exception:
            pass
        
    except Exception as e:
        logger.error(f"Erro ao gerar gráficos: {e}")

if __name__ == "__main__":
    logger = setup_logger()
    plot_cleaned_boxplots()