import logging
import os
import sys
import time

import numpy as np
import pandas as pd
from tabulate import tabulate

from .feature_normalizer import FeatureNormalizer
from .predict_new_data import get_available_models, predict_ip_classification

# python query.py input_dataset.csv output_dataset.csv
# python query.py input_dataset.csv output_dataset.csv model_name

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "Total_test1.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "datasets", "test_normalized.csv")


def setup_logging(log_file="outputs/model_prediction.log"):
    """Configures the logging system.

    Args:
        log_file (str): Path to the log file. Defaults to "outputs/model_prediction.log".

    Returns:
        logging.Logger: Configured logger instance.
    """
    # Create the outputs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


def main():
    """Main function to execute model predictions."""
    # Initialize logger
    logger = setup_logging()

    # Directory where models are saved
    models_dir = os.path.join(BASE_DIR, "data", "models")

    # Input and output dataset paths
    dataset_path = DATASET_PATH  # Dataset to be normalized
    output_path = OUTPUT_PATH  # Normalized output dataset

    # If command-line arguments are provided, use them
    # if len(sys.argv) > 1:
    #     dataset_path = sys.argv[1]
    # if len(sys.argv) > 2:
    #     output_path = sys.argv[2]

    logger.info(f"Input dataset: {dataset_path}")
    logger.info(f"Normalized output dataset: {output_path}")

    # Get list of available models
    available_models = get_available_models(models_dir)
    logger.info(f"\nAvailable models: {available_models}")

    # If a specific model is provided as a command-line argument, use it
    selected_model = None
    if len(sys.argv) > 3:
        selected_model = sys.argv[3]
        if selected_model not in available_models:
            logger.error(f"Model '{selected_model}' not found in available models.")
            raise ValueError(f"Model '{selected_model}' not found in available models.")
        available_models = [selected_model]
        logger.info(f"Using selected model: {selected_model}")

    # Normalize the dataset
    logger.info("\nNormalizing the dataset...")
    start_time = time.time()
    file_normalizer = FeatureNormalizer()
    file_normalizer.aplicar_pesos_em_novo_dataset(dataset_path, output_path)
    normalization_time = time.time() - start_time
    logger.info(f"Normalization time: {normalization_time:.4f} seconds")

    # Run predictions for each model and measure execution time
    results = []
    sample_predictions = {}
    logger.info("\nRunning predictions for each model...")
    for model_name in available_models:
        logger.info(f"\nModel: {model_name}")
        start_time = time.time()

        predictions = predict_ip_classification(
            input_path=output_path, models_dir=models_dir, model_name=model_name
        )

        end_time = time.time()
        execution_time = end_time - start_time

        # Log the structure of the predictions DataFrame for debugging
        logger.info(f"Predictions DataFrame columns: {predictions.columns.tolist()}")

        # Check if the 'classification' column exists
        if "classification" not in predictions.columns:
            logger.error(
                f"Column 'classification' not found in predictions for model: {model_name}"
            )
            raise KeyError(
                f"Column 'classification' not found in predictions for model: {model_name}"
            )

        # Unique classifications and their counts
        class_counts = predictions["classification"].value_counts().to_dict()
        sample_predictions[model_name] = predictions

        # Add results to the list
        results.append(
            {
                "Model": model_name,
                "Time (s)": execution_time,
                "Number of IPs": len(predictions),
                "Class Distribution": class_counts,
            }
        )

    # Create DataFrame with the results
    results_df = pd.DataFrame(results)

    # Sort results by execution time
    results_df = results_df.sort_values("Time (s)")

    # Format times for display
    results_df["Time (s)"] = results_df["Time (s)"].map(lambda x: f"{x:.4f}")

    # Show results table
    logger.info("\n=== MODEL PERFORMANCE RESULTS ===")
    logger.info(
        "\n" + tabulate(results_df, headers="keys", tablefmt="grid", showindex=False)
    )

    # Select the fastest model for detailed analysis
    fastest_model = results_df.iloc[0]["Model"]
    logger.info(f"\nFastest model: {fastest_model}")
    logger.info("\nSample predictions from the fastest model:")
    sample_size = min(5, len(sample_predictions[fastest_model]))
    logger.info("\n" + str(sample_predictions[fastest_model].head(sample_size)))

    # Export results to CSV
    results_path = "outputs/model_timing_results.csv"
    results_df.to_csv(results_path, index=False)
    logger.info(f"\nResults exported to: {results_path}")


if __name__ == "__main__":
    try:
        main()
        logger = logging.getLogger(__name__)
        logger.info("\nPipeline completed successfully!")
    except Exception as e:
        logging.getLogger(__name__).error(f"Error during pipeline execution: {str(e)}")
        print(f"Error during pipeline execution: {str(e)}")
