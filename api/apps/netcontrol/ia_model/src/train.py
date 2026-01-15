import logging
import os
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.decomposition import PCA
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from config.config import PARAM_GRID

from .models import create_cnn_model, get_models
from .visualization import plot_learning_curves, plot_learning_curves_cnn


def setup_training_logger():
    """
    Setup specific logger for training module
    """

    logs_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(logs_dir, f"training_{timestamp}.log")

    logger = logging.getLogger("training")
    logger.setLevel(logging.INFO)

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def train_and_evaluate_models(
    X_train, X_test, y_train, y_test, models_dir, images_dir, use_smote=False
):
    """
    Train and evaluate models WITH DATA LEAKAGE CORRECTION.

    Args:
        X_train (pd.DataFrame): Training features
        X_test (pd.DataFrame): Test features
        y_train (pd.Series): Training labels
        y_test (pd.Series): Test labels
        models_dir (str): Directory to save models
        images_dir (str): Directory to save images
        use_smote (bool): Whether to apply SMOTE to training set

    Returns:
        tuple: (results, execution_times, trained_models)
    """
    logger = setup_training_logger()

    logger.info("=" * 60)
    logger.info("STARTING MODEL TRAINING AND EVALUATION")
    logger.info("=" * 60)
    logger.info(f"Training set shape: {X_train.shape}")
    logger.info(f"Test set shape: {X_test.shape}")
    logger.info(f"SMOTE enabled: {use_smote}")
    logger.info(f"Models directory: {models_dir}")
    logger.info(f"Images directory: {images_dir}")

    if use_smote:
        logger.info("Applying SMOTE for class balancing...")
        smote = SMOTE(random_state=42)
        try:
            X_train_processed, y_train_processed = smote.fit_resample(X_train, y_train)
            logger.info(
                f"SMOTE applied successfully. New training set shape: {X_train_processed.shape}"
            )

            if isinstance(y_train_processed, np.ndarray):
                y_train_series = pd.Series(y_train_processed)
            else:
                y_train_series = y_train_processed

            logger.info(
                f"Class distribution after SMOTE: {y_train_series.value_counts().to_dict()}"
            )
        except Exception as e:
            logger.error(f"Error applying SMOTE: {e}")
            raise
    else:
        logger.info("Using original training set without SMOTE")
        X_train_processed = X_train.copy()
        y_train_processed = y_train.copy()

        if isinstance(y_train, np.ndarray):
            y_train_series = pd.Series(y_train)
        else:
            y_train_series = y_train

        logger.info(
            f"Original class distribution: {y_train_series.value_counts().to_dict()}"
        )

    input_shape = (X_train_processed.shape[1], 1)
    logger.info(f"Input shape for CNN: {input_shape}")

    logger.info("Initializing models...")
    try:
        models = get_models(input_shape, use_smote=use_smote)
        logger.info("Models loaded from models.py")
    except TypeError:
        logger.warning(
            "get_models() doesn't support use_smote parameter, using adapted version"
        )
        models = get_models_adapted(input_shape, use_smote)
        logger.info("Models loaded from adapted function")
    except Exception as e:
        logger.error(f"Error loading models: {e}")
        logger.info("Falling back to adapted models function")
        models = get_models_adapted(input_shape, use_smote)

    logger.info(f"Models to train: {list(models.keys())}")

    results = {}
    execution_times = {}
    trained_models = {}

    os.makedirs(models_dir, exist_ok=True)
    logger.info(f"Models will be saved to: {models_dir}")

    for name, model in models.items():
        logger.info("-" * 40)
        logger.info(f"Training {name} model...")
        start_time = time.time()

        try:
            if name == "CNN":
                logger.info("Processing CNN model...")
                model, hyperparameters = model
                logger.info(f"CNN hyperparameters: {hyperparameters}")

                X_train_reshaped = X_train_processed.values.reshape(
                    X_train_processed.shape[0], X_train_processed.shape[1], 1
                )
                X_test_reshaped = X_test.values.reshape(
                    X_test.shape[0], X_test.shape[1], 1
                )
                logger.info(
                    f"Data reshaped for CNN - Train: {X_train_reshaped.shape}, Test: {X_test_reshaped.shape}"
                )

                logger.info("Starting CNN training...")
                history = model.fit(
                    X_train_reshaped,
                    y_train_processed,
                    epochs=hyperparameters["epochs"],
                    batch_size=hyperparameters["batch_size"],
                    validation_split=0.2,
                    verbose=0,
                )
                logger.info(
                    f"CNN training completed after {hyperparameters['epochs']} epochs"
                )

                train_score = model.evaluate(
                    X_train_reshaped, y_train_processed, verbose=0
                )[1]
                test_score = model.evaluate(X_test_reshaped, y_test, verbose=0)[1]
                logger.info(f"CNN Training Score: {train_score:.4f}")
                logger.info(f"CNN Test Score: {test_score:.4f}")

                results[name] = {
                    "Best Parameters": hyperparameters,
                    "Train Score": train_score,
                    "Test Score": test_score,
                }
                trained_models[name] = model

                try:
                    plot_learning_curves_cnn(history, name, images_dir)
                    logger.info(f"Learning curves generated for {name}")
                except Exception as e:
                    logger.warning(
                        f"Failed to generate learning curves for {name}: {e}"
                    )

                try:
                    model_path = os.path.join(models_dir, f"CNN_model.keras")
                    model.save(model_path)
                    logger.info(f"CNN model saved to: {model_path}")
                except Exception as e:
                    logger.error(f"Failed to save CNN model: {e}")

            else:

                logger.info(f"Processing {name} with GridSearchCV...")
                logger.info(
                    f"Parameter grid for {name}: {PARAM_GRID.get(name, 'Not found')}"
                )

                grid_search = GridSearchCV(
                    model,
                    PARAM_GRID[name],
                    cv=5,
                    scoring="f1_weighted",
                    n_jobs=-1,
                    verbose=1,
                )

                logger.info(f"Starting GridSearchCV for {name}...")
                try:
                    grid_search.fit(X_train_processed, y_train_processed)
                    logger.info(f"GridSearchCV completed for {name}")
                    logger.info(
                        f"Best parameters for {name}: {grid_search.best_params_}"
                    )
                    logger.info(
                        f"Best CV score for {name}: {grid_search.best_score_:.4f}"
                    )
                except Exception as e:
                    logger.error(f"Error during GridSearchCV for {name}: {e}")
                    continue

                train_score = grid_search.score(X_train_processed, y_train_processed)
                test_score = grid_search.score(X_test, y_test)
                logger.info(f"{name} Training Score: {train_score:.4f}")
                logger.info(f"{name} Test Score: {test_score:.4f}")

                results[name] = {
                    "Best Parameters": grid_search.best_params_,
                    "Train Score": train_score,
                    "Test Score": test_score,
                }
                trained_models[name] = grid_search.best_estimator_

                try:
                    plot_learning_curves(
                        grid_search.best_estimator_,
                        X_train_processed,
                        y_train_processed,
                        name,
                        images_dir,
                    )
                    logger.info(f"Learning curves generated for {name}")
                except Exception as e:
                    logger.warning(
                        f"Failed to generate learning curves for {name}: {e}"
                    )

                try:
                    model_path = os.path.join(models_dir, f"{name}_model.joblib")
                    joblib.dump(grid_search.best_estimator_, model_path)
                    logger.info(f"{name} model saved to: {model_path}")
                except Exception as e:
                    logger.error(f"Failed to save {name} model: {e}")

            execution_time = time.time() - start_time
            execution_times[name] = execution_time
            logger.info(f"{name} training completed in {execution_time:.2f} seconds")

        except Exception as e:
            logger.error(f"Critical error training {name}: {e}")
            execution_time = time.time() - start_time
            execution_times[name] = execution_time
            continue

    logger.info("=" * 60)
    logger.info("TRAINING SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Successfully trained models: {list(trained_models.keys())}")
    logger.info("Execution times:")
    for model_name, exec_time in execution_times.items():
        logger.info(f"  {model_name}: {exec_time:.2f} seconds")

    if results:
        logger.info("Training and test scores:")
        for model_name, result in results.items():
            logger.info(f"  {model_name}:")
            logger.info(f"    Train Score: {result['Train Score']:.4f}")
            logger.info(f"    Test Score: {result['Test Score']:.4f}")
    else:
        logger.warning("No models were successfully trained!")

    logger.info("=" * 60)
    logger.info("MODEL TRAINING AND EVALUATION COMPLETED")
    logger.info("=" * 60)

    return results, execution_times, trained_models


def get_models_adapted(input_shape, use_smote):
    """
    Adapted function to use original models.py with correct configurations.

    Args:
        input_shape: Shape for CNN input layer
        use_smote: Whether SMOTE is being used (affects class_weight)

    Returns:
        dict: Dictionary of model names and model objects
    """
    logger = logging.getLogger("training")
    logger.info("Creating adapted models...")

    cnn_model, cnn_params = create_cnn_model(input_shape)
    logger.info("CNN model imported from models.py")

    class_weight = None if use_smote else "balanced"
    logger.info(f"Class weight setting: {class_weight} (SMOTE: {use_smote})")

    models_dict = {
        "Random Forest": RandomForestClassifier(
            class_weight=class_weight, random_state=42
        ),
        "SVM": SVC(class_weight=class_weight, probability=True, random_state=42),
        "Neural Network": MLPClassifier(
            max_iter=1000,
            random_state=42,
            learning_rate_init=0.001,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=10,
            hidden_layer_sizes=(100, 50),
            activation="relu",
            solver="adam",
            batch_size="auto",
            shuffle=True,
            verbose=False,
        ),
        "Extra Trees": ExtraTreesClassifier(class_weight=class_weight, random_state=42),
        "Decision Tree": DecisionTreeClassifier(
            class_weight=class_weight, random_state=42
        ),
        "KNN": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("pca", PCA()),
                ("knn", KNeighborsClassifier()),
            ]
        ),
        "CNN": (cnn_model, cnn_params),
    }

    logger.info(f"Created {len(models_dict)} models: {list(models_dict.keys())}")
    return models_dict


def train_and_evaluate_models_with_balancing(
    X_train, X_test, y_train, y_test, models_dir, images_dir
):
    """
    Compatibility function with old code.
    DEPRECATED: Use train_and_evaluate_models_corrected() with use_smote parameter.

    This function is maintained for backward compatibility but should not be used
    in new code. Use train_and_evaluate_models_corrected() instead.
    """
    logger = logging.getLogger("training")
    logger.warning(
        "Using deprecated function train_and_evaluate_models_with_balancing()"
    )
    logger.warning(
        "Please use train_and_evaluate_models() with use_smote parameter"
    )

    return train_and_evaluate_models(
        X_train, X_test, y_train, y_test, models_dir, images_dir, use_smote=False
    )
