import logging
import os
import pickle
import sys
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Model directory
# MODELS_DIR = "data/models"  # For models without SMOTE
MODELS_DIR = "data/models_s"      # For models with SMOTE

# Choose model to use
MODEL_NAME = "Decision Tree"  
# Available options:
# - "Random Forest" 
# - "SVM"
# - "Neural Network" 
# - "Extra Trees"
# - "Decision Tree"
# - "KNN"
# - "CNN"
SCALER_PARAMS_FILE = "scaler_params.pkl"


class IPClassificationPredictor:
    """
    Class for IP classification prediction using pre-trained models
    Works with dataset_ip.csv structure and applies same normalization as training
    """

    def __init__(
        self, models_dir=MODELS_DIR, scaler_params_file=SCALER_PARAMS_FILE, model_name=MODEL_NAME
    ):
        """
        Initialize the IP Classification Predictor

        Args:
            models_dir (str): Directory containing trained models
            scaler_params_file (str): Path to scaler parameters file
            model_name (str): Name of the model to use. Options:
                - "Random Forest" (default)
                - "SVM" 
                - "Neural Network"
                - "Extra Trees"
                - "Decision Tree"
                - "KNN"
                - "CNN"
        """
        self.models_dir = models_dir
        self.scaler_params_file = scaler_params_file
        self.model_name = model_name
        self.model = None
        self.label_encoder = None
        self.scalers = None
        self.scaler_columns = None
        self.feature_ranges = None


        self.available_models = {
            "Random Forest": "Random Forest_model.joblib",
            "SVM": "SVM_model.joblib", 
            "Neural Network": "Neural Network_model.joblib",
            "Extra Trees": "Extra Trees_model.joblib",
            "Decision Tree": "Decision Tree_model.joblib",
            "KNN": "KNN_model.joblib",
            "CNN": "CNN_model.keras"
        }

        self.risk_mapping = {
            "unknown": 1,
            "none": 2,
            "low": 3,
            "medium": 4,
            "high": 5,
            "critical": 6,
        }

        self.expected_input_columns = [
            "ip_address",
            "abuseipdb_confidence_score",
            "abuseipdb_total_reports",
            "abuseipdb_num_distinct_users",
            "ipvoid_detection_count",
            "risk_recommended_pulsedive",
            "virustotal_reputation",
            "virustotal_harmless",
            "virustotal_malicious",
            "virustotal_undetected",
            "virustotal_suspicious",
        ]

        self.model_feature_columns = [
            "abuseipdb_confidence_score",
            "abuseipdb_total_reports",
            "abuseipdb_num_distinct_users",
            "ipvoid_detection_count",
            "risk_recommended_pulsedive",
            "virustotal_reputation",
            "virustotal_harmless",
            "virustotal_malicious",
            "virustotal_undetected",
            "virustotal_suspicious",
        ]

        self.logger = self._setup_logger()

        self._load_scaler_params()
        self._load_model_components()

    def _setup_logger(self):
        """Setup logging configuration"""
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = os.path.join(logs_dir, f"ip_prediction_{timestamp}.log")

        logger = logging.getLogger(f"ip_predictor_{timestamp}")
        logger.setLevel(logging.INFO)

        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        file_handler = logging.FileHandler(log_filename)
        console_handler = logging.StreamHandler(sys.stdout)

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def _load_scaler_params(self):
        """Load scaler parameters from training"""
        if os.path.exists(self.scaler_params_file):
            try:
                with open(self.scaler_params_file, "rb") as f:
                    scaler_data = pickle.load(f)

                self.scalers = scaler_data["scalers"]
                self.scaler_columns = scaler_data["columns"]
                self.feature_ranges = scaler_data["feature_ranges"]

                self.logger.info(
                    f"Scaler parameters loaded from: {self.scaler_params_file}"
                )
                self.logger.info(f"Scaler columns: {self.scaler_columns}")
            except Exception as e:
                self.logger.error(f"Error loading scaler parameters: {e}")
                self.scalers = None
        else:
            self.logger.error(
                f"Scaler parameters file not found: {self.scaler_params_file}"
            )
            self.scalers = None

    def _load_model_components(self):
        """Load specified model and label encoder"""
        try:
           
            if self.model_name not in self.available_models:
                available_names = list(self.available_models.keys())
                self.logger.error(f"Invalid model name: {self.model_name}")
                self.logger.error(f"Available models: {available_names}")
                return False

            
            model_filename = self.available_models[self.model_name]
            model_path = os.path.join(self.models_dir, model_filename)
            
            if os.path.exists(model_path):
                if self.model_name == "CNN":
                    
                    try:
                        import tensorflow as tf
                        self.model = tf.keras.models.load_model(model_path)
                        self.logger.info(f"CNN model loaded: {model_path}")
                    except ImportError:
                        self.logger.error("TensorFlow not available. Cannot load CNN model.")
                        return False
                else:
                  
                    self.model = joblib.load(model_path)
                    self.logger.info(f"{self.model_name} model loaded: {model_path}")
            else:
                self.logger.error(f"{self.model_name} model not found: {model_path}")
                return False

            
            label_encoder_path = os.path.join(self.models_dir, "label_encoder.joblib")
            if os.path.exists(label_encoder_path):
                self.label_encoder = joblib.load(label_encoder_path)
                self.logger.info(f"Label encoder loaded: {label_encoder_path}")
                self.logger.info(
                    f"Available classes: {list(self.label_encoder.classes_)}"
                )
            else:
                self.logger.error(f"Label encoder not found: {label_encoder_path}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error loading model components: {e}")
            return False

    def _dict_to_dataframe(self, data_dict):
        """
        Convert dictionary to DataFrame

        Args:
            data_dict: Dictionary with IP data

        Returns:
            pd.DataFrame: DataFrame with the data
        """

        if isinstance(data_dict, dict) and any(
            key in data_dict for key in ["ip_address", "abuseipdb_confidence_score"]
        ):
            return pd.DataFrame([data_dict])

        elif isinstance(data_dict, list):
            return pd.DataFrame(data_dict)

        elif isinstance(data_dict, dict):
            return pd.DataFrame(data_dict)

        else:
            raise ValueError("Unsupported dictionary format")

    def _validate_and_prepare_data(self, df):
        """
        Validate and prepare data to match dataset_ip.csv structure

        Args:
            df (pd.DataFrame): Input DataFrame

        Returns:
            pd.DataFrame: DataFrame with validated structure
        """
        self.logger.info(f"Input columns: {list(df.columns)}")

        missing_cols = set(self.expected_input_columns) - set(df.columns)

        if missing_cols:
            self.logger.error(f"Missing required columns: {missing_cols}")
            self.logger.info("Expected columns (same as dataset_ip.csv):")
            for col in self.expected_input_columns:
                self.logger.info(f"  - {col}")

            raise ValueError(
                f"Missing required columns: {missing_cols}. Input must match dataset_ip.csv structure."
            )

        df = df[self.expected_input_columns].copy()

        self.logger.info("Data structure validated - matches dataset_ip.csv format")
        return df

    def _handle_missing_values(self, df):
        """
        Handle missing values (same strategy as training preprocessing)

        Args:
            df (pd.DataFrame): DataFrame with possible missing values

        Returns:
            pd.DataFrame: DataFrame with missing values handled
        """

        numerical_cols = [
            col
            for col in self.model_feature_columns
            if col != "risk_recommended_pulsedive"
        ]

        for col in numerical_cols:
            if col in df.columns:

                if df[col].isna().all():
                    df[col] = 0
                    self.logger.warning(f"Column {col} is all NaN - filled with 0")
                else:
                    median_val = df[col].median()
                    df[col] = df[col].fillna(median_val)
                    if df[col].isna().sum() > 0:
                        self.logger.info(
                            f"Filled {df[col].isna().sum()} missing values in {col} with median: {median_val}"
                        )

        if "risk_recommended_pulsedive" in df.columns:
            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].fillna(
                "medium"
            )
            self.logger.info(
                "Filled missing risk_recommended_pulsedive values with 'medium'"
            )

        return df

    def _encode_categorical_columns(self, df):
        """
        Encode categorical columns (same as training preprocessing)

        Args:
            df (pd.DataFrame): DataFrame with categorical columns

        Returns:
            pd.DataFrame: DataFrame with encoded columns
        """
        if "risk_recommended_pulsedive" in df.columns:
            self.logger.info("Encoding risk_recommended_pulsedive column")
            original_values = df["risk_recommended_pulsedive"].value_counts()
            self.logger.info(f"Original values: {original_values.to_dict()}")

            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].map(
                self.risk_mapping
            )

            unmapped_count = df["risk_recommended_pulsedive"].isna().sum()
            if unmapped_count > 0:
                self.logger.warning(
                    f"Found {unmapped_count} unmapped risk values - filling with 'medium' (4)"
                )
                df["risk_recommended_pulsedive"] = df[
                    "risk_recommended_pulsedive"
                ].fillna(4)

            encoded_values = df["risk_recommended_pulsedive"].value_counts()
            self.logger.info(f"Encoded values: {encoded_values.to_dict()}")

        return df

    def _normalize_features(self, df):
        """
        Normalize features using the same scalers from training

        Args:
            df (pd.DataFrame): DataFrame with features to normalize

        Returns:
            pd.DataFrame: DataFrame with normalized features
        """
        if self.scalers is None:
            raise ValueError("Scaler parameters not loaded. Cannot normalize features.")

        self.logger.info("Applying normalization using training scalers")

        for col in self.model_feature_columns:
            if col in df.columns and col in self.scalers:
                scaler_info = self.scalers[col]
                scaler = scaler_info["scaler"]

                values = df[col].values.reshape(-1, 1)
                df[col] = scaler.transform(values).flatten()

                self.logger.info(
                    f"Normalized {col}: range [{df[col].min():.3f}, {df[col].max():.3f}]"
                )
            elif col not in self.scalers:
                self.logger.warning(f"No scaler found for column: {col}")

        self.logger.info("Feature normalization completed")
        return df

    def preprocess_for_prediction(self, input_data):
        """
        Preprocess data for prediction (same pipeline as training)

        Args:
            input_data: CSV file path, dictionary or DataFrame

        Returns:
            pd.DataFrame: Processed DataFrame ready for prediction
        """
        self.logger.info("Starting preprocessing for prediction...")

        if isinstance(input_data, str):
            if not os.path.exists(input_data):
                raise FileNotFoundError(f"CSV file not found: {input_data}")
            df = pd.read_csv(input_data)
            self.logger.info(
                f"Dataset loaded from CSV: {df.shape[0]} rows, {df.shape[1]} columns"
            )

            if df.empty:
                raise ValueError("CSV file is empty")

        elif isinstance(input_data, (dict, list)):
            df = self._dict_to_dataframe(input_data)
            self.logger.info(
                f"Dataset created from dictionary: {df.shape[0]} rows, {df.shape[1]} columns"
            )
        elif isinstance(input_data, pd.DataFrame):
            df = input_data.copy()
            self.logger.info(
                f"DataFrame received: {df.shape[0]} rows, {df.shape[1]} columns"
            )
        else:
            raise ValueError(
                "Unsupported input type. Use CSV path, dictionary or DataFrame."
            )

        df = self._validate_and_prepare_data(df)

        df = self._handle_missing_values(df)

        df = self._encode_categorical_columns(df)

        df = self._normalize_features(df)

        self.logger.info(
            f"Preprocessing completed: {df.shape[0]} rows, {df.shape[1]} columns"
        )
        return df

    def predict_classification(self, input_data, output_file=None):
        """
        Predict IP classification

        Args:
            input_data: CSV file path, dictionary or DataFrame (must match dataset_ip.csv structure)
            output_file (str, optional): Path to save results CSV

        Returns:
            dict: Dictionary with predictions for each IP
        """
        self.logger.info("Starting IP classification prediction")

        if self.model is None or self.label_encoder is None:
            return {"error": "Model or label encoder not loaded properly"}

        try:

            processed_df = self.preprocess_for_prediction(input_data)

            feature_columns = self.model_feature_columns
            features = processed_df[feature_columns].values

            self.logger.info(
                f"Making predictions for {len(features)} IPs using {len(feature_columns)} features"
            )
            self.logger.info(f"Feature columns: {feature_columns}")

            if self.model_name == "CNN":

                features_reshaped = features.reshape(features.shape[0], features.shape[1], 1)
                prediction_probs = self.model.predict(features_reshaped, verbose=0)
                predictions = np.argmax(prediction_probs, axis=1)
                confidences = np.max(prediction_probs, axis=1)
            else:

                predictions = self.model.predict(features)
                
                if hasattr(self.model, "predict_proba"):
                    probabilities = self.model.predict_proba(features)
                    confidences = np.max(probabilities, axis=1)
                else:
                    confidences = [None] * len(predictions)

            predicted_labels = self.label_encoder.inverse_transform(predictions)

            results = {}

            for i in range(len(predicted_labels)):

                if "ip_address" in processed_df.columns:
                    ip_key = processed_df.iloc[i]["ip_address"]
                else:
                    ip_key = f"ip_{i+1}"

                results[ip_key] = {
                    "classification": predicted_labels[i],
                    "confidence": (
                        float(confidences[i]) if confidences[i] is not None else None
                    ),
                    "model_used": self.model_name,
                }

            self.logger.info(f"Predictions completed for {len(results)} IPs")

            prediction_counts = {}
            for result in results.values():
                label = result["classification"]
                prediction_counts[label] = prediction_counts.get(label, 0) + 1

            self.logger.info("Prediction summary:")
            for label, count in prediction_counts.items():
                self.logger.info(f"  {label}: {count}")

            if output_file:
                results_df = processed_df.copy()
                results_df["predicted_classification"] = predicted_labels
                results_df["prediction_confidence"] = confidences
                results_df["model_used"] = self.model_name
                results_df["prediction_timestamp"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                results_df.to_csv(output_file, index=False)
                self.logger.info(f"Results saved to: {output_file}")

            return results

        except Exception as e:
            self.logger.error(f"Error during prediction: {e}")
            return {"error": str(e)}


if __name__ == "__main__":
    
    # Option 1: Single IP (must have exact dataset_ip.csv structure)
    single_ip_data = {
        "ip_address": "192.168.1.100",
        "abuseipdb_confidence_score": 25,
        "abuseipdb_total_reports": 3,
        "abuseipdb_num_distinct_users": 2,
        "ipvoid_detection_count": 1,
        "risk_recommended_pulsedive": "medium",
        "virustotal_reputation": 0,
        "virustotal_harmless": 45,
        "virustotal_malicious": 1,
        "virustotal_undetected": 25,
        "virustotal_suspicious": 0,
    }

    # Option 2: CSV file (must match dataset_ip.csv structure)
    # csv_file_path = "datasets/Total_test1.csv"
    # output_csv_path = "datasets/prediction_results.csv"

    # Initialize predictor with chosen model
    predictor = IPClassificationPredictor(MODELS_DIR, SCALER_PARAMS_FILE, MODEL_NAME)

    # Make prediction
    # For single IP:
    results = predictor.predict_classification(single_ip_data)

    # For CSV file:
    # results = predictor.predict_classification(csv_file_path, output_csv_path)

    