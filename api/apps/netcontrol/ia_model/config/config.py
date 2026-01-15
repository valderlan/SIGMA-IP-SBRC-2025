import os
from datetime import datetime


def get_pipeline_config(use_smote: bool) -> dict:
    """
    Generates and returns the main configuration dictionary for the pipeline.

    Args:
        use_smote (bool): Flag to enable or disable SMOTE.

    Returns:
        dict: A dictionary with all pipeline settings.
    """
    return {
        "data_file": "datasets/dataset_ip_norm.csv",
        "test_size": 0.2,
        "random_state": 42,
        "score_cols": SCORE_COLS,
        "use_smote": use_smote,
        "corrected_pipeline": True,  # Flag to indicate the use of corrected pipeline
        "timestamp": datetime.now().isoformat(),
    }


# Directory configurations
BASE_DIR = (
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if __file__
    else os.getcwd()
)
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(DATA_DIR, "models")
MODELS_S_DIR = os.path.join(DATA_DIR, "models_s")  # For SMOTE models
EXPERIMENTS_DIR = os.path.join(DATA_DIR, "experiments")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")  # Full path for consistency
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# All directories that need to be created
REQUIRED_DIRECTORIES = [
    DATA_DIR,
    MODELS_DIR,
    MODELS_S_DIR,
    EXPERIMENTS_DIR,
    DATASETS_DIR,
    LOGS_DIR,
]


def create_project_directories():
    """
    Create all required project directories.
    This function is called explicitly rather than on import.

    Returns:
        dict: Dictionary with all created directory paths
    """
    created_dirs = {}

    for directory in REQUIRED_DIRECTORIES:
        try:
            os.makedirs(directory, exist_ok=True)
            created_dirs[os.path.basename(directory)] = directory
        except Exception as e:

            fallback_dir = os.path.join(os.getcwd(), os.path.basename(directory))
            os.makedirs(fallback_dir, exist_ok=True)
            created_dirs[os.path.basename(directory)] = fallback_dir

    return created_dirs


def create_experiment_directory(experiment_name=None):
    """
    Create a new experiment directory with timestamp.

    Args:
        experiment_name (str, optional): Custom experiment name

    Returns:
        str: Path to the created experiment directory
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if experiment_name:
        exp_dir_name = f"{experiment_name}_{timestamp}"
    else:
        exp_dir_name = f"experiment_{timestamp}"

    experiment_dir = os.path.join(EXPERIMENTS_DIR, exp_dir_name)
    images_dir = os.path.join(experiment_dir, "images")

    for directory in [experiment_dir, images_dir]:
        os.makedirs(directory, exist_ok=True)

    return experiment_dir


def initialize_project():
    """
    Initialize the complete project structure.
    Call this function at the start of your main pipeline.

    Returns:
        dict: Dictionary with all created directory paths
    """
    return create_project_directories()


# Plot configurations
PLOT_STYLE = "ggplot"
FIGURE_SIZE = [9, 4]
FONT_SIZE = 12
LABEL_SIZE = 14
TITLE_SIZE = 16

# Dataset configurations
DATASET_PATH = os.path.join(
    DATASETS_DIR, "dataset_ip_norm.csv"
)  # Updated to use consistent path
TEST_SIZE = 0.2
RANDOM_STATE = 42

# Feature columns for scoring
SCORE_COLS = [
    "abuseipdb_confidence_score",
    "abuseipdb_total_reports",
    "abuseipdb_num_distinct_users",
    "apivoid_risk_score",
    "apivoid_blacklists_detection_rate",
    "risk_recommended_pulsedive",
    "virustotal_reputation",
    "virustotal_harmless",
    "virustotal_malicious",
    "virustotal_undetected",
    "virustotal_suspicious",
]

# Hyperparameter grids for model tuning
PARAM_GRID = {
    "Random Forest": {
        "n_estimators": [100, 200],
        "max_depth": [4, 5, 7],
        "min_samples_split": [2, 4],
        "max_features": ["sqrt", "log2"],
        "min_samples_leaf": [20, 25, 30],
    },
    "SVM": {
        "C": [0.001, 0.01, 0.1],
        "kernel": ["rbf", "linear"],
        "gamma": ["scale", "auto"],
    },
    "Neural Network": {
        "hidden_layer_sizes": [(30,), (30, 15)],
        "alpha": [0.01, 0.1],
        "learning_rate": ["adaptive"],
    },
    "Extra Trees": {
        "n_estimators": [100, 200],
        "max_depth": [4, 5, 7],
        "min_samples_split": [2, 4],
        "min_samples_leaf": [20, 25, 30],
    },
    "Decision Tree": {
        "max_depth": [4, 5, 6],
        "min_samples_split": [2, 4],
        "min_samples_leaf": [20, 25, 30],
        "max_features": ["sqrt", "log2"],
    },
    "KNN": {
        "pca__n_components": [0.65, 0.70, 0.75],
        "knn__n_neighbors": [31, 33, 35],
        "knn__weights": ["uniform"],
        "knn__metric": ["euclidean"],
        "knn__p": [2],
        "knn__leaf_size": [50],
    },
    "AdaBoost": {
        'n_estimators': [50, 100],
        'learning_rate': [0.1, 0.5, 1.0],
    },
     "Voting": {
        'voting': ['soft'],
        'weights': [[1, 1, 1], [2, 1, 1], [1, 2, 1]], # Pesos para RF, SVM, KNN
    },
     "Stacking": {
        'final_estimator__n_estimators': [50, 100],
        'final_estimator__max_depth': [5, 10],
    },
}

# Default experiment configuration
DEFAULT_EXPERIMENT_CONFIG = {
    "data_file": DATASET_PATH,
    "test_size": TEST_SIZE,
    "random_state": RANDOM_STATE,
    "score_cols": SCORE_COLS,
    "use_smote": False,
    "corrected_pipeline": True,
}


LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "log_dir": LOGS_DIR,
    "max_log_files": 10,
}


TRAINING_CONFIG = {
    "cv_folds": 5,
    "scoring": "accuracy",
    "n_jobs": -1,
    "verbose": 1,
}


VISUALIZATION_CONFIG = {
    "dpi": 300,
    "bbox_inches": "tight",
    "facecolor": "white",
    "edgecolor": "none",
}


PATHS = {
    "dataset": DATASET_PATH,
    "models": MODELS_DIR,
    "models_smote": MODELS_S_DIR,
    "experiments": EXPERIMENTS_DIR,
    "logs": LOGS_DIR,
    "data": DATA_DIR,
    "datasets": DATASETS_DIR,
}
