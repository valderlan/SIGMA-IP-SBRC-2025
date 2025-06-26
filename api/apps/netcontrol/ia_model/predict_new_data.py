import logging
import os

import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model

from .config.config import SCORE_COLS


def setup_logging(log_file="outputs/prediction.log"):
    """Configures the logging system.

    Args:
        log_file (str): Path to the log file. Defaults to "outputs/prediction.log".

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


def predict_ip_classification(input_path, models_dir, model_name):
    """Predicts the classification (blacklist, whitelist, or suspicious) for new IPs
    using the specified model.

    Args:
        input_path (str): Path to the CSV file with the new data.
        models_dir (str): Directory where the trained models are saved.
        model_name (str): Name of the model to be used (e.g., 'Random Forest', 'SVM', etc.).

    Returns:
        pd.DataFrame: DataFrame with the predictions from the selected model.

    Raises:
        FileNotFoundError: If the input file or model is not found.
        KeyError: If required features are missing in the input file.
    """
    logger = logging.getLogger(__name__)

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"File {input_path} not found.")

    logger.info("Loading new data...")
    new_df = pd.read_csv(input_path)

    missing_cols = [col for col in SCORE_COLS if col not in new_df.columns]
    if missing_cols:
        raise KeyError(f"Missing features in the file: {missing_cols}")

    X_new = new_df[SCORE_COLS]

    logger.info("Loading LabelEncoder...")
    le = joblib.load(os.path.join(models_dir, "label_encoder.joblib"))

    if model_name == "CNN":
        model_file = "CNN_model.keras"
    else:
        model_file = f"{model_name}_model.joblib"

    model_path = os.path.join(models_dir, model_file)
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model {model_file} not found in {models_dir}")

    logger.info(f"Predicting with model {model_name}...")
    if model_name == "CNN":
        model = load_model(model_path)
        X_new_reshaped = X_new.values.reshape(X_new.shape[0], X_new.shape[1], 1)
        y_pred = model.predict(X_new_reshaped)
        y_pred = np.argmax(y_pred, axis=1)
    else:
        model = joblib.load(model_path)
        y_pred = model.predict(X_new)

    predictions = le.inverse_transform(y_pred)

    results_df = pd.DataFrame()
    if "ip_address" in new_df.columns:
        results_df["ip_address"] = new_df["ip_address"]
    results_df["classification"] = predictions
    results_df["model_used"] = model_name

    return results_df


def get_available_models(models_dir):
    """Retrieves the list of available models in the specified directory.

    Args:
        models_dir (str): Directory where the models are saved.

    Returns:
        list: List of available model names.
    """
    available_models = []
    for file in os.listdir(models_dir):
        if file.endswith("_model.joblib"):
            model_name = file.replace("_model.joblib", "")
            available_models.append(model_name)
        elif file == "CNN_model.keras":
            available_models.append("CNN")
    return available_models


if __name__ == "__main__":
    import argparse

    # Initialize logger
    logger = setup_logging()

    parser = argparse.ArgumentParser(description="Predict classification for new IPs")
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the input CSV file (e.g., datasets/test.csv)",
    )
    parser.add_argument(
        "models_dir",
        type=str,
        help="Path to the directory containing the models (e.g., data/experiments/experiment_20250108_102855/models)",
    )
    parser.add_argument(
        "model_name", type=str, help="Name of the model to use (e.g., 'Random Forest')"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to save the output CSV file (e.g., outputs/predictions.csv)",
    )

    args = parser.parse_args()

    try:
        available_models = get_available_models(args.models_dir)
        logger.info(f"\nAvailable models: {available_models}")

        if args.model_name not in available_models:
            raise ValueError(
                f"Model '{args.model_name}' not available. Choose one of the listed models."
            )

        predictions_df = predict_ip_classification(
            args.input_file, args.models_dir, args.model_name
        )

        logger.info("\nPrediction results:")
        logger.info("\n" + str(predictions_df))

        if args.output:
            predictions_df.to_csv(args.output, index=False)
            logger.info(f"\nResults saved to: {args.output}")

    except Exception as e:
        logger.error(f"Error during prediction: {str(e)}")
