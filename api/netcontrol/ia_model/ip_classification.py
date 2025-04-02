import json
import logging
import os

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from feature_normalizer import FeatureNormalizer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(BASE_DIR, 'outputs')
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
IP_CLASSIFICATION_LOG_PATH = os.path.join(OUTPUTS_DIR, 'ip_classification.log')


def setup_logging(log_file=IP_CLASSIFICATION_LOG_PATH):
    """Configures the logging system.

    Args:
        log_file (str): Path to the log file. Defaults to "outputs/ip_classification.log".

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


def classify_ips_and_generate_plots(config_path=CONFIG_PATH, output_dir=OUTPUTS_DIR):
    """Classifies IPs using FeatureNormalizer and generates plots.

    This function uses FeatureNormalizer to process the dataset, classify IPs,
    and generate distribution plots.

    Args:
        config_path (str): Path to the configuration file. Defaults to "config.json".
        output_dir (str): Directory to save the plots. Defaults to "outputs".

    Returns:
        pd.DataFrame: A DataFrame containing the final classified results.
    """

    logger = setup_logging()

    logger.info("=== STARTING IP CLASSIFICATION AND PLOT GENERATION ===")

    logger.info("1. Initializing FeatureNormalizer...")
    normalizer = FeatureNormalizer(config_path)
    config = normalizer.config

    logger.info("2. Applying normalization and weights to the dataset...")

    scores = normalizer.aplicar_pesos_em_novo_dataset(
        output_path=os.path.join(output_dir, "result_with_weights.csv")
    )

    logger.info("3. Calculating final score...")

    score_columns = [col for col in scores.columns if col != "ip_address"]
    scores_sum = scores[score_columns].sum(axis=1)

    logger.info("4. Adding classification...")
    classification = pd.cut(
        scores_sum,
        bins=[-np.inf, 0.2, 0.4, np.inf],
        labels=["Whitelist", "Suspicious", "Blacklist"],
    )

    logger.info("5. Creating final DataFrame with classification...")
    final_result = scores.copy()
    final_result["final_score"] = scores_sum
    final_result["classification"] = classification

    logger.info("6. Dropping 'final_score' column...")
    final_result = final_result.drop(columns=["final_score"])

    logger.info("7. Saving classified dataset...")

    original_file_path = config.get("input_file")
    original_file_name = os.path.basename(original_file_path)
    original_file_name_without_ext = os.path.splitext(original_file_name)[0]

    classified_file_name = f"{original_file_name_without_ext}_classified.csv"

    datasets_dir = "datasets"
    os.makedirs(datasets_dir, exist_ok=True)

    output_path = os.path.join(datasets_dir, classified_file_name)
    final_result.to_csv(output_path, index=False)
    logger.info(f"Classified dataset saved at: {output_path}")

    distribution = classification.value_counts()
    logger.info("\nClassification Distribution:\n%s", distribution)

    logger.info("\n8. Generating distribution plots...")
    os.makedirs(output_dir, exist_ok=True)

    plt.rcParams.update(
        {
            "font.size": 26,
            "axes.labelsize": 26,
            "axes.titlesize": 26,
            "xtick.labelsize": 22,
            "ytick.labelsize": 22,
            "legend.fontsize": 24,
        }
    )

    logger.info("   Generating line plot...")
    sorted_scores = np.sort(scores_sum)
    count = np.arange(1, len(sorted_scores) + 1)

    plt.figure(figsize=(10, 7))
    plt.plot(count, sorted_scores, linewidth=2)
    plt.xlabel("Count (sorted)")
    plt.ylabel("Final Score")
    plt.grid(True, alpha=0.3)

    z = np.polyfit(count, sorted_scores, 1)
    p = np.poly1d(z)
    plt.plot(count, p(count), "r--", alpha=0.8, label="Linear Trend")
    plt.legend(loc="upper left")
    plt.tight_layout()

    line_plot_path = os.path.join(output_dir, "score_distribution_line.png")
    plt.savefig(line_plot_path, bbox_inches="tight", dpi=300)
    plt.close()
    logger.info(f"   Line plot saved at: {line_plot_path}")

    logger.info("   Generating histogram...")
    plt.figure(figsize=(10, 7))
    n, bins, patches = plt.hist(scores_sum, bins=20, edgecolor="black")

    for patch, left_edge in zip(patches, bins[:-1]):
        if left_edge < 0.2:
            patch.set_facecolor("#1f77b4")
        elif 0.2 <= left_edge < 0.4:
            patch.set_facecolor("#808080")
        else:
            patch.set_facecolor("red")

    plt.xlabel("Final Score")
    plt.ylabel("Frequency")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    histogram_path = os.path.join(output_dir, "score_distribution_histogram.png")
    plt.savefig(histogram_path, bbox_inches="tight", dpi=300)
    plt.close()
    logger.info(f"   Histogram saved at: {histogram_path}")

    logger.info("\n=== IP CLASSIFICATION AND PLOT GENERATION COMPLETED ===")

    return final_result


if __name__ == "__main__":
    result = classify_ips_and_generate_plots()
    logger = logging.getLogger(__name__)
    logger.info("\nProcessing completed successfully!")
