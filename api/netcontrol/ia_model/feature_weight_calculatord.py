import json
import logging
import os

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from util.map_risk_level import map_risk_level


def setup_logging(log_file="outputs/weight_calculation.log"):
    """Configures the logging system.

    Args:
        log_file (str): Path to the log file. Defaults to "outputs/weight_calculation.log".

    Returns:
        logging.Logger: Configured logger instance.
    """

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


def calculate_final_weights(
    config_path="config.json", output_dir="weights", output_file="final_weights.json"
):
    """Calculates the final feature weights and saves them.

    This function follows the same logic as feature_analyzer.py but focuses solely on weight calculation.
    The original calculation method is preserved (without normalizing variance), but with enhanced
    visualizations and logs for better understanding of the process.

    Args:
        config_path (str): Path to the configuration file. Defaults to "config.json".
        output_dir (str): Directory where the weights will be saved. Defaults to "outputs".
        output_file (str): Output file name for the weights. Defaults to "final_weights.json".

    Returns:
        dict: A dictionary containing the calculated weights.

    Raises:
        FileNotFoundError: If the configuration file or dataset is not found.
    """

    logger = setup_logging()

    logger.info("=== STARTING WEIGHT CALCULATION ===")

    logger.info("1. Loading configuration...")
    if not os.path.exists(config_path):
        logger.error(f"Configuration file '{config_path}' not found.")
        raise FileNotFoundError(f"Configuration file '{config_path}' not found.")

    with open(config_path, "r") as file:
        config = json.load(file)

    logger.info("2. Loading dataset...")
    file_path = config["input_file"]
    if not os.path.exists(file_path):
        logger.error(f"Dataset '{file_path}' not found.")
        raise FileNotFoundError(f"Dataset '{file_path}' not found.")

    df = pd.read_csv(file_path)

    logger.info("3. Categorizing risk_recommended_pulsedive...")
    if "risk_recommended_pulsedive" in df.columns:
        df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].apply(
            map_risk_level
        )

    logger.info("4. Getting feature information...")
    feature_ranges = config.get("feature_ranges", {})
    selected_features = list(feature_ranges.keys())
    inverted_features = config.get("inverted_features", [])

    logger.info("5. Selecting features...")
    df_selected = df[selected_features].copy()

    logger.info("6. Normalizing features...")
    df_norm = pd.DataFrame()
    for feature, (min_val, max_val) in feature_ranges.items():
        if feature in df_selected.columns:

            clipped_values = df_selected[feature].clip(lower=min_val, upper=max_val)

            range_size = max_val - min_val
            if range_size > 0:
                normalized_values = (clipped_values - min_val) / range_size
            else:
                normalized_values = clipped_values * 0

            df_norm[feature] = normalized_values

    logger.info("7. Inverting specific features...")
    for feature in inverted_features:
        if feature in df_norm.columns:
            df_norm[feature] = 1 - df_norm[feature]

    logger.info("8. Calculating variances...")
    variances = pd.DataFrame(
        {
            "Feature": df_norm.columns,
            "Variance": np.var(df_norm, axis=0),
            "Type": [
                (
                    "Blacklist"
                    if col not in inverted_features
                    else "Inverted (Whitelist)"
                )
                for col in df_norm.columns
            ],
        }
    ).sort_values("Variance", ascending=False)

    logger.info("\nVariance Analysis:\n%s", variances.to_string(index=False))
    
    # Estatísticas das variâncias para análise
    logger.info("   Variance statistics: min=%.6f, max=%.6f, mean=%.6f", 
                variances["Variance"].min(), 
                variances["Variance"].max(), 
                variances["Variance"].mean())

    logger.info("9. Calculating correlations...")
    corr_matrix = df_norm.corr()
    mean_corr = corr_matrix.abs().mean()
    correlations = pd.DataFrame(
        {
            "Feature": df_norm.columns,
            "Mean_Correlation": mean_corr,
            "Type": [
                (
                    "Blacklist"
                    if col not in inverted_features
                    else "Inverted (Whitelist)"
                )
                for col in df_norm.columns
            ],
        }
    ).sort_values("Mean_Correlation", ascending=False)

    logger.info("\nMean Correlation Analysis:\n%s", correlations.to_string(index=False))
    
    # Estatísticas das correlações para análise
    logger.info("   Correlation statistics: min=%.6f, max=%.6f, mean=%.6f", 
                correlations["Mean_Correlation"].min(), 
                correlations["Mean_Correlation"].max(), 
                correlations["Mean_Correlation"].mean())

    logger.info("10. Calculating composite score...")
    composite_score = pd.DataFrame(
        {
            "Feature": variances["Feature"],
            "Variance": variances["Variance"],
            "Correlation": correlations.set_index("Feature").loc[
                variances["Feature"], "Mean_Correlation"
            ],
        }
    )

    # Usando o cálculo original (sem normalização adicional da variância)
    composite_score["Importance_Score"] = (
        composite_score["Variance"] + composite_score["Correlation"]
    ) / 2
    
    # Adicionar coluna de contribuição para diagnóstico
    composite_score["Variance_Contribution"] = composite_score["Variance"] / (
        composite_score["Variance"] + composite_score["Correlation"]
    ) * 100
    
    composite_score["Correlation_Contribution"] = composite_score["Correlation"] / (
        composite_score["Variance"] + composite_score["Correlation"]
    ) * 100

    composite_score["Type"] = [
        "Blacklist" if col not in inverted_features else "Inverted (Whitelist)"
        for col in composite_score["Feature"]
    ]

    # Ordenar pelo score de importância para melhor visualização
    composite_score = composite_score.sort_values("Importance_Score", ascending=False)

    logger.info(
        "\nImportance Score Calculations:\n%s", 
        composite_score[["Feature", "Variance", "Correlation", "Importance_Score", "Type"]].to_string(index=False)
    )
    
    logger.info(
        "\nContribution Analysis (how much each metric contributes to the final score):\n%s", 
        composite_score[["Feature", "Variance_Contribution", "Correlation_Contribution", "Importance_Score"]].to_string(index=False)
    )

    # Análise da escala dos valores
    logger.info("\nScale Analysis (checking if variance and correlation are on comparable scales):")
    var_range = variances["Variance"].max() - variances["Variance"].min()
    corr_range = correlations["Mean_Correlation"].max() - correlations["Mean_Correlation"].min()
    
    logger.info(f"   Variance range: [{variances['Variance'].min():.6f}, {variances['Variance'].max():.6f}], span: {var_range:.6f}")
    logger.info(f"   Correlation range: [{correlations['Mean_Correlation'].min():.6f}, {correlations['Mean_Correlation'].max():.6f}], span: {corr_range:.6f}")
    
    if variances["Variance"].max() <= 0.25:
        logger.info("   NOTE: Variance values are naturally low (max ≤ 0.25) because data was normalized to [0,1]")
        logger.info("   This explains why no additional variance normalization is needed - scales are already comparable")
    
    ratio = variances["Variance"].max() / correlations["Mean_Correlation"].max()
    logger.info(f"   Max variance / max correlation ratio: {ratio:.6f}")
    
    if ratio < 0.5:
        logger.info("   Correlation dominates the importance score (variance is relatively small)")
    elif ratio > 2.0:
        logger.info("   Variance dominates the importance score (correlation is relatively small)")
    else:
        logger.info("   Variance and correlation have comparable influence on the importance score")

    logger.info("11. Calculating normalized weights...")
    normalized_score = (
        composite_score["Importance_Score"] / composite_score["Importance_Score"].sum()
    )

    combined_weights = pd.DataFrame(
        {
            "Feature": composite_score["Feature"],
            "Final_Weight": normalized_score,
            "Type": composite_score["Type"],
        }
    ).sort_values("Final_Weight", ascending=False)

    logger.info(
        "\nFinal Calculated Weights:\n%s", combined_weights.to_string(index=False)
    )

    logger.info("12. Saving weights in JSON...")
    os.makedirs(output_dir, exist_ok=True)

    file_path = os.path.join(output_dir, output_file)
    weights_dict = combined_weights.set_index("Feature")["Final_Weight"].to_dict()

    with open(file_path, "w") as file:
        json.dump(weights_dict, file, indent=4)

    logger.info(f"Final weights saved at: {file_path}")

    logger.info("13. Generating correlation matrix plot...")
    plt.figure(figsize=(12, 10))
    sns.heatmap(corr_matrix, annot=True, fmt=".2f", cmap="coolwarm", center=0)
    plt.title("Feature Correlation Matrix")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()

    plot_path = os.path.join(output_dir, "correlation_matrix.png")
    plt.savefig(plot_path)
    logger.info(f"Correlation matrix plot saved at: {plot_path}")
    plt.close()
    
    # Gerando gráficos adicionais para visualizar a importância
    logger.info("14. Generating importance visualization plots...")
    
    # Gráfico comparando variância e correlação
    plt.figure(figsize=(14, 8))
    bar_width = 0.35
    features = composite_score["Feature"]
    x = np.arange(len(features))
    
    plt.bar(x - bar_width/2, composite_score["Variance"], bar_width, label='Variância', color='#1f77b4')
    plt.bar(x + bar_width/2, composite_score["Correlation"], bar_width, label='Correlação Média', color='#ff7f0e')
    
    plt.xlabel('Features')
    plt.ylabel('Valor')
    plt.title('Comparação entre Variância e Correlação Média')
    plt.xticks(x, features, rotation=45, ha='right')
    plt.legend()
    plt.tight_layout()
    
    comparison_plot_path = os.path.join(output_dir, "variance_correlation_comparison.png")
    plt.savefig(comparison_plot_path)
    logger.info(f"Variance and correlation comparison plot saved at: {comparison_plot_path}")
    plt.close()
    
    # Gráfico de barras para visualizar a contribuição da variância e correlação
    plt.figure(figsize=(14, 8))
    
    # Dados para o gráfico de barras empilhadas
    var_contrib = composite_score["Variance"] / 2  # Dividir por 2 para representar a média
    corr_contrib = composite_score["Correlation"] / 2  # Dividir por 2 para representar a média
    
    plt.bar(features, var_contrib, label='Contribuição da Variância', color='#1f77b4')
    plt.bar(features, corr_contrib, bottom=var_contrib, label='Contribuição da Correlação', color='#ff7f0e')
    
    plt.xlabel('Features')
    plt.ylabel('Contribuição para o Score de Importância')
    plt.title('Composição do Score de Importância')
    plt.xticks(rotation=45, ha='right')
    plt.legend()
    plt.tight_layout()
    
    contribution_plot_path = os.path.join(output_dir, "importance_composition.png")
    plt.savefig(contribution_plot_path)
    logger.info(f"Importance composition plot saved at: {contribution_plot_path}")
    plt.close()
    
    # Gráfico final de barras para os pesos normalizados
    plt.figure(figsize=(14, 8))
    combined_weights_sorted = combined_weights.sort_values("Final_Weight", ascending=True)
    
    plt.barh(combined_weights_sorted["Feature"], combined_weights_sorted["Final_Weight"], color='#2ca02c')
    plt.xlabel('Peso Final Normalizado')
    plt.ylabel('Features')
    plt.title('Pesos Finais das Features')
    plt.tight_layout()
    
    weights_plot_path = os.path.join(output_dir, "final_weights.png")
    plt.savefig(weights_plot_path)
    logger.info(f"Final weights plot saved at: {weights_plot_path}")
    plt.close()

    # Gráfico de pizza para visualizar a contribuição percentual de cada feature
    plt.figure(figsize=(12, 10))
    plt.pie(combined_weights["Final_Weight"], labels=combined_weights["Feature"], 
            autopct='%1.1f%%', startangle=90, shadow=True)
    plt.axis('equal')  # Assegura que o gráfico seja desenhado como um círculo
    plt.title('Distribuição Percentual dos Pesos Finais')
    
    pie_plot_path = os.path.join(output_dir, "weights_distribution_pie.png")
    plt.savefig(pie_plot_path)
    logger.info(f"Weights distribution pie chart saved at: {pie_plot_path}")
    plt.close()

    logger.info("=== WEIGHT CALCULATION COMPLETED ===")

    return weights_dict


if __name__ == "__main__":
    weights = calculate_final_weights()
    logger = logging.getLogger(__name__)
    logger.info("\nWeights calculated successfully!")