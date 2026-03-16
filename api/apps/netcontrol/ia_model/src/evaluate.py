import os

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    classification_report,
    cohen_kappa_score,
    f1_score,
    log_loss,
    matthews_corrcoef,
    precision_recall_fscore_support,
    roc_auc_score,
)


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
        "Balanced_Accuracy": [],
        "F1-Score": [],
        "F1-Macro": [],
        "Precision": [],
        "Recall": [],
        "Cohen_Kappa": [],
        "ROC_AUC": [],
        "Log_Loss": [],
        "MCC": [],
        "Brier_Score": [],
    }

    model_names = []

    for name, model in trained_models.items():

        y_pred_proba = None
        y_pred = None

        if name == "CNN":
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred_proba = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred_proba, axis=1)
        else:
            y_pred = model.predict(X_test)

            if hasattr(model, "predict_proba"):
                y_pred_proba = model.predict_proba(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        balanced_accuracy = balanced_accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        f1_macro = f1_score(y_test, y_pred, average="macro")
        precision, recall, _, _ = precision_recall_fscore_support(
            y_test, y_pred, average="weighted"
        )
        cohen_kappa = cohen_kappa_score(y_test, y_pred)
        mcc = matthews_corrcoef(y_test, y_pred)

        metrics_dict["Accuracy"].append(accuracy)
        metrics_dict["Balanced_Accuracy"].append(balanced_accuracy)
        metrics_dict["F1-Score"].append(f1)
        metrics_dict["F1-Macro"].append(f1_macro)
        metrics_dict["Precision"].append(precision)
        metrics_dict["Recall"].append(recall)
        metrics_dict["Cohen_Kappa"].append(cohen_kappa)
        metrics_dict["MCC"].append(mcc)

        if y_pred_proba is not None and y_pred_proba.shape[1] > 1:
            try:
                roc_auc = roc_auc_score(
                    y_test, 
                    y_pred_proba, 
                    multi_class="ovr", 
                    average="weighted"
                )
                metrics_dict["ROC_AUC"].append(roc_auc)
                
                logloss = log_loss(y_test, y_pred_proba)

                n_classes = y_pred_proba.shape[1]
                brier_scores = []
                for i in range(n_classes):
                    y_test_binary = (y_test == i).astype(int)
                    brier_scores.append(
                        brier_score_loss(y_test_binary, y_pred_proba[:, i])
                    )
                brier_score_final = np.mean(brier_scores)

                metrics_dict["Log_Loss"].append(logloss)
                metrics_dict["Brier_Score"].append(brier_score_final)

            except Exception as e:
                print(f"Warning: Log Loss or Brier Score failed for {name}: {e}")
                metrics_dict["Log_Loss"].append(np.nan)
                metrics_dict["Brier_Score"].append(np.nan)
        else:
            metrics_dict["Log_Loss"].append(np.nan)
            metrics_dict["Brier_Score"].append(np.nan)
            print(
                f"Warning: Cannot calculate Log Loss/Brier Score for {name} (no predict_proba/multi-class proba)."
            )

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


def generate_classification_reports(trained_models, X_test, y_test, le):
    """
    Generates classification reports (string) for all trained models.

    Args:
        trained_models: Dictionary with trained models
        X_test: Test features
        y_test: Test labels (integer-encoded)
        le: LabelEncoder used to transform classes

    Returns:
        dict: Dictionary with the model name and the classification report string
    """
    reports = {}
    target_names = le.classes_.astype(str).tolist()

    for name, model in trained_models.items():
        y_pred = None

        if name == "CNN":
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred_proba = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred_proba, axis=1)
        else:
            y_pred = model.predict(X_test)
        try:
            report_str = classification_report(
                y_test, y_pred, target_names=target_names, zero_division=0
            )
            reports[name] = report_str
        except Exception as e:
            reports[name] = f"Error generating report: {e}"
            print(f"Warning: classification_report failed for {name}: {e}")
    return reports


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
