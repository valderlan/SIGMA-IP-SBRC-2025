import logging
import os
import sys
import traceback
from datetime import datetime

import pandas as pd

from src.dataset_classifier import WeightedVotingClassifier
from src.normalize import preprocess_ip_dataset

sys.path.append(os.path.join(os.getcwd(), "src"))


def setup_preprocessing_logger():
    """
    Setup logger for the data preprocessing pipeline
    """

    logs_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(logs_dir, f"data_preprocessing_{timestamp}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_filename), logging.StreamHandler(sys.stdout)],
    )

    return logging.getLogger(__name__)


def check_and_create_directories():
    """
    Ensure all required directories exist
    """
    directories = ["datasets", "logs", "src"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def classify_dataset(input_file, output_file):
    """
    Classify the dataset using weighted voting classifier

    Args:
        input_file (str): Path to input CSV file
        output_file (str): Path to output classified CSV file

    Returns:
        str: Path to the classified dataset
    """
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("DATASET CLASSIFICATION PROCESS")
    logger.info("=" * 60)

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    logger.error(
        "Failed to import WeightedVotingClassifier from src.dataset_classifier"
    )
    logger.info(f"Classifying dataset: {input_file}")

    classifier = WeightedVotingClassifier()

    df = pd.read_csv(input_file)
    logger.info(f"Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns")

    df_processed = classifier.preprocess_data(df)
    df_norm = classifier.normalize_features(df_processed)
    ground_truth = classifier.create_ground_truth(df_processed)
    optimal_weights = classifier.determine_optimal_weights(df_norm, ground_truth)
    final_predictions, confidence_scores = classifier.classify_with_weighted_voting(
        df_norm, optimal_weights
    )

    df_classified = df.copy()
    df_classified["classification"] = final_predictions
    df_classified["confidence_score"] = confidence_scores
    df_classified["ground_truth"] = ground_truth
    df_classified["prediction_match"] = [
        gt == pred for gt, pred in zip(ground_truth, final_predictions)
    ]

    accuracy = sum(df_classified["prediction_match"]) / len(df_classified)
    logger.info(f"Classification accuracy: {accuracy:.3f}")

    df_classified.to_csv(output_file, index=False)
    logger.info(f"Classified dataset saved to: {output_file}")
    logger.info(f"Classification distribution:")
    for class_name, count in pd.Series(final_predictions).value_counts().items():
        logger.info(
            f"  {class_name}: {count} ({count/len(final_predictions)*100:.1f}%)"
        )

    return output_file


def normalize_dataset(input_file, output_file):
    """
    Normalize the classified dataset for ML training

    Args:
        input_file (str): Path to input classified CSV file
        output_file (str): Path to output normalized CSV file

    Returns:
        str: Path to the normalized dataset
    """
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("DATASET NORMALIZATION PROCESS")
    logger.info("=" * 60)

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    logger.error("Failed to import preprocess_ip_dataset from src.normalize")

    logger.info(f"Normalizing dataset: {input_file}")

    df_normalized = preprocess_ip_dataset(input_file, output_file)

    logger.info(f"Normalized dataset saved to: {output_file}")
    logger.info(f"Final dataset shape: {df_normalized.shape}")

    return output_file


def validate_dataset(file_path, expected_columns=None):
    """
    Validate that the dataset has the expected structure

    Args:
        file_path (str): Path to CSV file to validate
        expected_columns (list): List of expected column names

    Returns:
        bool: True if validation passes
    """
    logger = logging.getLogger(__name__)

    if not os.path.exists(file_path):
        logger.error(f"Validation failed: File not found - {file_path}")
        return False

    try:
        df = pd.read_csv(file_path)
        logger.info(f"Validating dataset: {file_path}")
        logger.info(f"  Shape: {df.shape}")
        logger.info(f"  Columns: {list(df.columns)}")

        if expected_columns:
            missing_cols = set(expected_columns) - set(df.columns)
            if missing_cols:
                logger.error(f"Missing expected columns: {missing_cols}")
                return False

        if len(df) == 0:
            logger.error("Dataset is empty")
            return False

        logger.info("Dataset validation passed")
        return True

    except Exception as e:
        logger.error(f"Validation error: {e}")
        return False


def run_complete_preprocessing_pipeline():
    """
    Run the complete data preprocessing pipeline

    Returns:
        dict: Results summary with file paths and statistics
    """
    logger = setup_preprocessing_logger()

    logger.info("=" * 80)
    logger.info("COMPLETE DATA PREPROCESSING PIPELINE STARTED")
    logger.info("=" * 80)

    check_and_create_directories()

    datasets_dir = "datasets"
    original_file = os.path.join(datasets_dir, "dataset_ip12.csv")
    classified_file = os.path.join(datasets_dir, "dataset_ip_classified.csv")
    normalized_file = os.path.join(datasets_dir, "dataset_ip_norm.csv")

    results = {"success": False, "files_created": [], "errors": [], "statistics": {}}

    try:

        logger.info("Step 1: Validating original dataset...")
        if not validate_dataset(original_file):
            raise FileNotFoundError(
                f"Original dataset validation failed: {original_file}"
            )

        df_original = pd.read_csv(original_file)
        results["statistics"]["original"] = {
            "rows": len(df_original),
            "columns": len(df_original.columns),
        }

        logger.info("Step 2: Classifying dataset...")
        classified_path = classify_dataset(original_file, classified_file)
        results["files_created"].append(classified_path)

        df_classified = pd.read_csv(classified_path)
        results["statistics"]["classified"] = {
            "rows": len(df_classified),
            "columns": len(df_classified.columns),
            "class_distribution": df_classified["classification"]
            .value_counts()
            .to_dict(),
        }

        logger.info("Step 3: Normalizing dataset...")
        normalized_path = normalize_dataset(classified_path, normalized_file)
        results["files_created"].append(normalized_path)

        df_normalized = pd.read_csv(normalized_path)
        results["statistics"]["normalized"] = {
            "rows": len(df_normalized),
            "columns": len(df_normalized.columns),
        }

        logger.info("Step 4: Final validation...")
        expected_ml_columns = [
            "ip",
            "classification",
            "risk_recommended_pulsedive",
            "abuseipdb_confidence_score",
            "abuseipdb_total_reports",
            "abuseipdb_num_distinct_users",
            "apivoid_risk_score",
            "apivoid_blacklists_detection_rate",
            "virustotal_reputation",
            "virustotal_harmless",
            "virustotal_malicious",
            "virustotal_undetected",
            "virustotal_suspicious",
        ]

        if not validate_dataset(normalized_path, expected_ml_columns):
            raise ValueError("Final dataset validation failed")

        results["success"] = True

        logger.info("=" * 80)
        logger.info("PREPROCESSING PIPELINE COMPLETED SUCCESSFULLY")
        logger.info("=" * 80)
        logger.info("Pipeline Summary:")
        logger.info(
            f"  Original dataset: {results['statistics']['original']['rows']} rows"
        )

        logger.info(
            f"  After classification: {results['statistics']['classified']['rows']} rows"
        )
        logger.info(
            f"  Final normalized: {results['statistics']['normalized']['rows']} rows"
        )

        logger.info("Class distribution:")
        for class_name, count in results["statistics"]["classified"][
            "class_distribution"
        ].items():
            logger.info(f"  {class_name}: {count}")

        logger.info("Files created:")
        for file_path in results["files_created"]:
            logger.info(f"  {file_path}")

        logger.info(f"ML-ready dataset: {normalized_path}")

    except Exception as e:
        logger.error(f"Pipeline failed: {str(e)}")
        results["errors"].append(str(e))
        results["success"] = False

        logger.error(f"Traceback: {traceback.format_exc()}")

    logger.info("=" * 80)
    logger.info("DATA PREPROCESSING PIPELINE FINISHED")
    logger.info("=" * 80)

    return results


if __name__ == "__main__":
    results = run_complete_preprocessing_pipeline()
