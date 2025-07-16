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

    composite_score["Importance_Score"] = (
        composite_score["Variance"] + composite_score["Correlation"]
    ) / 2

    composite_score["Type"] = [
        "Blacklist" if col not in inverted_features else "Inverted (Whitelist)"
        for col in composite_score["Feature"]
    ]

    logger.info(
        "\nImportance Score Calculations:\n%s", composite_score.to_string(index=False)
    )

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

    logger.info("=== WEIGHT CALCULATION COMPLETED ===")

    return weights_dict


if __name__ == "__main__":
    weights = calculate_final_weights()
    logger = logging.getLogger(__name__)
    logger.info("\nWeights calculated successfully!")
