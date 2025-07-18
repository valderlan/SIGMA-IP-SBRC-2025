import os

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support


def evaluate_models(trained_models, X_test, y_test):
    """
    Evaluate trained models using various metrics.

    Args:
        trained_models: Dictionary with trained models
        X_test: Test features
        y_test: Test labels

    Returns:
        pd.DataFrame: DataFrame with metrics for each model
    """
    metrics_dict = {
        "Accuracy": [],
        "F1-Score": [],
        "Precision": [],
        "Recall": [],
        "Harmonic_Mean": [],
    }

    model_names = []

    for name, model in trained_models.items():
        if name == "CNN":
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred, axis=1)
        else:
            y_pred = model.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        precision, recall, _, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted"
        )
        harmonic_mean = 2 * (precision * recall) / (precision + recall)

        metrics_dict["Accuracy"].append(accuracy)
        metrics_dict["F1-Score"].append(f1)
        metrics_dict["Precision"].append(precision)
        metrics_dict["Recall"].append(recall)
        metrics_dict["Harmonic_Mean"].append(harmonic_mean)
        model_names.append(name)

    metrics_df = pd.DataFrame(metrics_dict, index=model_names)
    return metrics_df


def evaluate_model_accuracy(trained_models, X_test, y_test, le):
    """
    Evaluates model accuracy on the test set.

    Args:
        trained_models: Dictionary with trained models
        X_test: Test set features
        y_test: True labels of the test set
        le: LabelEncoder used to transform classes

    Returns:
        pd.DataFrame: DataFrame with accuracy metrics for each model
    """
    accuracy_results = {}

    for name, model in trained_models.items():
        if name == "CNN":
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred, axis=1)
        else:
            y_pred = model.predict(X_test)

        y_pred_labels = le.inverse_transform(y_pred)
        y_test_labels = le.inverse_transform(y_test)

        correct_predictions = sum(y_pred_labels == y_test_labels)
        total_predictions = len(y_test_labels)
        accuracy = (correct_predictions / total_predictions) * 100

        accuracy_results[name] = {
            "Correct": correct_predictions,
            "Errors": total_predictions - correct_predictions,
            "Accuracy (%)": accuracy,
        }

    return pd.DataFrame(accuracy_results).T


def save_evaluation_results(metrics_df, accuracy_df, output_dir):
    """
    Save evaluation results to CSV files.

    Args:
        metrics_df: DataFrame with model metrics
        accuracy_df: DataFrame with accuracy results
        output_dir: Output directory path
    """
    metrics_df.to_csv(os.path.join(output_dir, "metrics_results.csv"))
    accuracy_df.to_csv(os.path.join(output_dir, "accuracy_results.csv"))
