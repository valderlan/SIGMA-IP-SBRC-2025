import matplotlib

matplotlib.use("Agg", force=True)

matplotlib.interactive(False)
import matplotlib.pyplot as plt

plt.switch_backend("Agg")
import os

import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import auc, confusion_matrix, roc_curve
from sklearn.model_selection import learning_curve
from sklearn.preprocessing import label_binarize

plt.rcParams["axes.prop_cycle"] = plt.cycler(
    color=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"]
)
plt.rcParams["lines.linewidth"] = 2
plt.rcParams["axes.grid"] = True
plt.rcParams["grid.alpha"] = 0.3

plt.rcParams["figure.max_open_warning"] = 0
plt.style.use("dark_background")
sns.set_style("darkgrid")
sns.set_palette("Set2")


def plot_feature_importance(model, model_name, feature_names, images_dir):
    """
    Generates and saves a feature importance plot for a model.

    Args:
        model: The trained model (must have the feature_importances_ attribute).
        model_name (str): The model name for the plot title.
        feature_names (list): List with feature names.
        images_dir (str): Directory to save the image.
    """
    if not hasattr(model, "feature_importances_"):
        print(
            f"The model {model_name} does not have the 'feature_importances_' attribute."
        )
        return

    importances = model.feature_importances_
    feature_importance_df = pd.DataFrame(
        {"Feature": feature_names, "Importance": importances}
    ).sort_values(by="Importance", ascending=False)

    plt.style.use("ggplot")
    plt.figure(figsize=(12, 8))
    sns.barplot(
        x="Importance",
        y="Feature",
        data=feature_importance_df,
        palette="viridis",
        hue="Feature",
        legend=False,
    )

    plt.title(f"Feature Importance - {model_name} Model", fontsize=16)
    plt.xlabel("Importance", fontsize=14)
    plt.ylabel("Feature", fontsize=14)
    plt.tight_layout()

    try:
        if not os.path.exists(images_dir):
            os.makedirs(images_dir)
        file_path = os.path.join(images_dir, f"feature_importance_{model_name}.png")
        plt.savefig(file_path)
        print(f"Feature importance plot saved to: {file_path}")
        plt.close()
    except Exception as e:
        print(f"Error saving feature importance plot: {e}")


def create_and_save_plot(func):
    """
    Decorator to properly handle plot creation and cleanup.
    """

    def wrapper(*args, **kwargs):
        plt.clf()
        try:
            return func(*args, **kwargs)
        finally:
            plt.close("all")

    return wrapper


@create_and_save_plot
def plot_feature_distributions(df, score_cols, images_dir):
    """
    Plot feature distributions for all score columns.

    Args:
        df: DataFrame with the data
        score_cols: List of score column names
        images_dir: Directory to save the plot
    """
    n_cols = 3
    n_rows = (len(score_cols) + n_cols - 1) // n_cols
    plt.figure(figsize=(15, n_rows * 4))

    for i, col in enumerate(score_cols, 1):
        plt.subplot(n_rows, n_cols, i)
        sns.histplot(data=df, x=col, kde=True)
        plt.title(f"Distribution of {col}")
        plt.xticks(rotation=45)

    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, "feature_distributions.png"))


@create_and_save_plot
def plot_correlation_matrix(df, score_cols, images_dir):
    """
    Plot correlation matrix between features.

    Args:
        df: DataFrame with the data
        score_cols: List of score column names
        images_dir: Directory to save the plot
    """
    plt.figure(figsize=(12, 8))
    correlation_matrix = df[score_cols].corr()
    sns.heatmap(correlation_matrix, annot=True, cmap="coolwarm", center=0, fmt=".2f")
    plt.title("Correlation Matrix between Features")
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, "correlation_matrix.png"),
        bbox_inches="tight",
        transparent=True,
    )


@create_and_save_plot
def plot_execution_times(execution_times, images_dir):
    """
    Plot model execution times.

    Args:
        execution_times: Dictionary with model names and their execution times
        images_dir: Directory to save the plot
    """
    plt.figure(figsize=(12, 6))
    sns.barplot(
        x=list(execution_times.keys()),
        y=list(execution_times.values()),
        color="#0D47A1",
    )
    plt.xlabel("Model", fontsize=18)
    plt.ylabel("Time (seconds)", fontsize=18)
    plt.xticks(fontsize=16, rotation=45)
    plt.yticks(fontsize=16)
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, "execution_times.png"),
        bbox_inches="tight",
        transparent=True,
    )


@create_and_save_plot
def plot_metrics_comparison(metrics_df, images_dir):
    """
    Plot comparison of metrics across all models.

    Args:
        metrics_df: DataFrame with metrics for all models
        images_dir: Directory to save the plots
    """

    cols_to_drop = [
        col for col in metrics_df.columns if "Mean" in col or "Média" in col
    ]
    metrics_df_filtered = metrics_df.drop(columns=cols_to_drop, errors="ignore")

    colors = [
        "blue",
        "orange",
        "darkgreen",
        "dimgray",
        "red",
        "purple",
        "brown",
        "pink",
        "olive",
        "cyan",
        "gold",      
        "teal"
    ]

    model_labels = list(metrics_df.index)

    plt.rc("font", size=18)
    plt.rc("axes", titlesize=12)
    plt.rc("axes", labelsize=12)
    plt.rc("xtick", labelsize=10)
    plt.rc("ytick", labelsize=10)
    plt.rc("legend", fontsize=8)
    plt.figure(figsize=(20, 16))

    metrics_df_filtered.plot(
        kind="bar", width=0.8, color=colors[: len(metrics_df_filtered.columns)]
    )
    plt.xlabel("Models", fontsize=14)
    plt.ylabel("Value", fontsize=14)
    plt.xticks(
        ticks=range(len(metrics_df_filtered.index)),
        labels=model_labels,
        rotation=45,
        fontsize=12,
    )
    plt.legend(title="Metrics", bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, "metrics_comparison.png"),
        bbox_inches="tight",
        transparent=True,
    )

    for metric in metrics_df_filtered.columns:
        plt.figure(figsize=(10, 6))
        sns.barplot(
            x=metrics_df_filtered.index, y=metrics_df_filtered[metric], color="#0D47A1"
        )
        plt.xlabel("Models", fontsize=16)
        plt.ylabel(metric, fontsize=16)
        plt.xticks(
            ticks=range(len(metrics_df_filtered.index)),
            labels=model_labels,
            rotation=45,
            fontsize=12,
        )
        plt.tight_layout()
        plt.savefig(
            os.path.join(images_dir, f'{metric.lower().replace(" ", "_")}.png'),
            bbox_inches="tight",
            transparent=True,
        )


@create_and_save_plot
def plot_confusion_matrices(trained_models, X_test, y_test, images_dir):
    """
    Plot confusion matrices for all trained models.

    Args:
        trained_models: Dictionary with model names and trained models
        X_test: Test features
        y_test: Test labels
        images_dir: Directory to save the plots
    """
    for name, model in trained_models.items():
        if name == "CNN":

            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred, axis=1)
        else:

            y_pred = model.predict(X_test)

        cm = confusion_matrix(y_test, y_pred)

        fig, ax = plt.subplots(figsize=(6, 6))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            ax=ax,
            annot_kws={"size": 24},
            cbar_kws={"label": "Scale", "shrink": 1.0},
        )
        ax.set_ylabel("Actual", fontsize=26)
        ax.set_xlabel("Predicted", fontsize=26)

        ax.set_xticklabels(ax.get_xticklabels(), fontsize=22)
        ax.set_yticklabels(ax.get_yticklabels(), fontsize=22)

        cbar = ax.collections[0].colorbar
        cbar.ax.tick_params(labelsize=16)
        cbar.set_label("Scale", size=20)

        file_name = f"confusion_matrix_{name.lower().replace(' ', '_')}.png"
        plt.tight_layout(pad=0.5)
        plt.savefig(
            os.path.join(images_dir, file_name),
            bbox_inches="tight",
            transparent=True,
        )
        plt.close(fig)


@create_and_save_plot
def plot_class_distribution(df, images_dir):
    """
    Plot the distribution of classes in the dataset.

    Args:
        df: DataFrame with the data
        images_dir: Directory to save the plot
    """
    if "classification" not in df.columns:
        raise ValueError("Column 'classification' not found in DataFrame")

    plt.figure(figsize=(10, 6))
    df["classification"].value_counts().plot(kind="bar", color="#0D47A1")
    plt.xlabel("Class", fontsize=16)
    plt.ylabel("Count", fontsize=16)
    plt.xticks(fontsize=16, rotation=45)
    plt.yticks(fontsize=16)
    plt.grid(True, axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, "class_distribution.png"),
        bbox_inches="tight",
        transparent=True,
    )


@create_and_save_plot
def plot_learning_curves(model, X_train, y_train, model_name, images_dir):
    """
    Plot learning curves for a model.

    Args:
        model: Trained model
        X_train: Training features
        y_train: Training labels
        model_name: Name of the model
        images_dir: Directory to save the plot
    """
    train_sizes, train_scores, val_scores = learning_curve(
        model,
        X_train,
        y_train,
        train_sizes=np.linspace(0.1, 1.0, 10),
        cv=5,
        scoring="f1_weighted",
        n_jobs=-1,
    )

    train_mean = np.mean(train_scores, axis=1)
    val_mean = np.mean(val_scores, axis=1)

    plt.figure(figsize=(10, 6))
    plt.plot(train_sizes, train_mean, label="Training Score", color="blue", marker="o")
    plt.plot(train_sizes, val_mean, label="Validation Score", color="red", marker="o")

    plt.xlabel("Training Set Size", fontsize=16)
    plt.ylabel("F1-Score", fontsize=16)
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=16)
    plt.legend(loc="lower right", fontsize=16)
    plt.grid(True)
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(
            images_dir, f'learning_curve_{model_name.lower().replace(" ", "_")}.png'
        ),
        bbox_inches="tight",
        transparent=True,
    )


@create_and_save_plot
def plot_learning_curves_cnn(history, model_name, images_dir):
    """
    Plot learning curves for CNN models using training history.

    Args:
        history: Training history from CNN model
        model_name: Name of the model
        images_dir: Directory to save the plot
    """
    train_sizes = np.linspace(0.1, 1.0, len(history.history["accuracy"]))
    train_scores = history.history["accuracy"]
    val_scores = history.history["val_accuracy"]

    plt.figure(figsize=(10, 6))
    plt.plot(
        train_sizes, train_scores, label="Training Score", color="blue", marker="o"
    )
    plt.plot(train_sizes, val_scores, label="Validation Score", color="red", marker="o")

    plt.xlabel("Training Set Proportion", fontsize=16)
    plt.ylabel("Accuracy", fontsize=16)
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=16)
    plt.legend(fontsize=16)
    plt.grid(True)
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, f"learning_curve_{model_name.lower()}.png"),
        bbox_inches="tight",
        transparent=True,
    )


@create_and_save_plot
def plot_roc_curves(trained_models, X_test, y_test, le, images_dir):
    """
    Plot One-vs-Rest ROC curves for all trained models (multi-class).

    Args:
        trained_models: Dictionary with model names and trained models
        X_test: Test features
        y_test: Test labels (integer-encoded)
        le: LabelEncoder used to transform classes
        images_dir: Directory to save the plots
    """
    class_labels = le.classes_
    n_classes = len(class_labels)
    y_test_binarized = label_binarize(y_test, classes=range(n_classes))

    for name, model in trained_models.items():
        try:

            if name == "CNN":
                X_test_reshaped = X_test.values.reshape(
                    X_test.shape[0], X_test.shape[1], 1
                )
                y_proba = model.predict(X_test_reshaped)
            elif hasattr(model, "predict_proba"):
                y_proba = model.predict_proba(X_test)
            else:
                print(
                    f"Skipping ROC plot for {name}: model does not have 'predict_proba'."
                )
                continue

            plt.figure(figsize=(8, 6))
            lw = 2

            for i in range(n_classes):
                fpr, tpr, _ = roc_curve(y_test_binarized[:, i], y_proba[:, i])
                roc_auc = auc(fpr, tpr)

                plt.plot(
                    fpr,
                    tpr,
                    lw=lw,
                    label=f"ROC curve of class {class_labels[i]} (AUC = {roc_auc:.2f})",
                )

            plt.plot([0, 1], [0, 1], color="navy", lw=lw, linestyle="--")
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel("False Positive Rate", fontsize=14)
            plt.ylabel("True Positive Rate", fontsize=14)
            plt.title(f"One-vs-Rest ROC Curves - {name}", fontsize=16)
            plt.legend(loc="lower right", fontsize=10)

            file_name = f"roc_curve_{name.lower().replace(' ', '_')}.png"
            plt.tight_layout(pad=0.5)
            plt.savefig(os.path.join(images_dir, file_name))
            plt.close()

        except Exception as e:
            print(f"Error generating ROC plot for {name}: {e}")


@create_and_save_plot
def plot_metrics_tables(results, metrics_df, images_dir):
    """
    Generate and save tables with model results and metrics.

    Args:
        results: DataFrame with model results including hyperparameters
        metrics_df: DataFrame with model metrics
        images_dir: Directory to save the plots
    """

    plt.figure(figsize=(15, len(results) * 0.5 + 1))
    plt.axis("off")

    headers = ["", "Best Parameters", "Train Score", "Test Score"]
    cell_data = []

    for model_name, row in results.iterrows():
        params = str(row.get("Best Parameters", "NaN"))
        train_score = f"{row.get('Train Score', 'NaN'):.6f}"
        test_score = f"{row.get('Test Score', 'NaN'):.6f}"
        cell_data.append([model_name, params, train_score, test_score])

    table = plt.table(
        cellText=cell_data,
        colLabels=headers,
        cellLoc="center",
        loc="center",
        colWidths=[0.15, 0.55, 0.15, 0.15],
    )

    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.2, 1.5)

    plt.title("Model Results:", pad=20)
    plt.savefig(
        os.path.join(images_dir, "model_results.png"),
        bbox_inches="tight",
        dpi=300,
        facecolor="black",
    )
    plt.close()

    plt.figure(figsize=(15, len(metrics_df) * 0.5 + 1))
    plt.axis("off")

    headers = [
        "",
        "Accuracy",
        "Balanced_Accuracy",
        "F1-Score",
        "F1-Macro",
        "Precision",
        "Recall",
        "Cohen_Kappa",
        "ROC_AUC",
        "Log_Loss",
        "MCC",
        "Brier_Score",
        "Overfit_Gap",
    ]

    col_map = {
        "Accuracy": ["Accuracy", "Acurácia"],
        "Balanced_Accuracy": ["Balanced_Accuracy", "Acurácia Balanceada"],
        "F1-Score": ["F1-Score"],
        "F1-Macro": ["F1-Macro"],
        "Precision": ["Precision", "Precisão"],
        "Recall": ["Recall"],
        "Cohen_Kappa": ["Cohen_Kappa", "Kappa de Cohen"],
        "ROC_AUC": ["ROC_AUC"],
        "Log_Loss": ["Log_Loss"],
        "MCC": ["MCC"],
        "Brier_Score": ["Brier_Score"],
        "Overfit_Gap": ["Overfit_Gap"],
    }

    def get_col_name(df, possible_names):
        for name in possible_names:
            if name in df.columns:
                return name
        return None

    cell_data = []

    for model_name, row in metrics_df.iterrows():
        cell_row = [model_name]
        for display_name in headers[1:]:
            col_name = get_col_name(metrics_df, col_map.get(display_name, []))
            if col_name and pd.notna(row.get(col_name)):
                cell_row.append(f"{row[col_name]:.4f}")
            else:
                cell_row.append("N/A")
        cell_data.append(cell_row)

    table = plt.table(
        cellText=cell_data,
        colLabels=headers,
        cellLoc="center",
        loc="center",
        colWidths=[0.1] + [0.070] * 12,
    )

    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1.5, 1.5)

    plt.title("Metrics Table:", pad=20)
    plt.savefig(
        os.path.join(images_dir, "metrics_table.png"),
        bbox_inches="tight",
        dpi=300,
        facecolor="black",
    )
    plt.close()
