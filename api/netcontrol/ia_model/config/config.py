import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
IMAGES_DIR = os.path.join(DATA_DIR, "images")
MODELS_DIR = os.path.join(DATA_DIR, "models")
EXPERIMENTS_DIR = os.path.join(DATA_DIR, "experiments")


for directory in [DATA_DIR, IMAGES_DIR, MODELS_DIR, EXPERIMENTS_DIR]:
    os.makedirs(directory, exist_ok=True)


PLOT_STYLE = "ggplot"
FIGURE_SIZE = [12, 8]
FONT_SIZE = 12
LABEL_SIZE = 14
TITLE_SIZE = 16


SCORE_COLS = [
    "abuseipdb_confidence_score",
    "abuseipdb_total_reports",
    "abuseipdb_num_distinct_users",
    "virustotal_reputation",
    "ipvoid_Detection_Count",
    "risk_recommended_pulsedrive",
    "virustotal_reputation",
    "virustotal_harmless",
    "virustotal_malicious",
    "virustotal_undetected",
    "virustotal_suspicious",
]


PARAM_GRID = {
    "Random Forest": {
        "n_estimators": [100, 200],
        "max_depth": [8, 10, 12],
        "min_samples_split": [2, 4],
        "max_features": ["sqrt", "log2"],
        "min_samples_leaf": [3, 5, 10],
    },
    "SVM": {
        "C": [0.01, 0.1, 1],
        "kernel": ["rbf", "linear"],
        "gamma": ["scale", "auto"],
    },
    "Neural Network": {
        "hidden_layer_sizes": [(50,), (50, 25)],
        "alpha": [0.001, 0.01],
        "learning_rate": ["adaptive"],
    },
    "Extra Trees": {
        "n_estimators": [100, 200],
        "max_depth": [10, 12, 15],
        "min_samples_split": [2, 4],
    },
    "Decision Tree": {
        "max_depth": [6, 8, 10],
        "min_samples_split": [2, 4],
        "min_samples_leaf": [3, 5, 10],
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
}
