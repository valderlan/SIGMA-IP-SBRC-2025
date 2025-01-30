import matplotlib

matplotlib.use("Agg", force=True)

matplotlib.interactive(False)
import matplotlib.pyplot as plt

plt.switch_backend("Agg")
import os

import numpy as np
import seaborn as sns
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import learning_curve

plt.rcParams["figure.max_open_warning"] = 0
plt.style.use("dark_background")
sns.set_style("darkgrid")


def create_and_save_plot(func):

    def wrapper(*args, **kwargs):
        plt.clf()
        try:
            return func(*args, **kwargs)
        finally:
            plt.close("all")

    return wrapper


@create_and_save_plot
def plot_feature_distributions(df, score_cols, images_dir):

    n_cols = 3
    n_rows = (len(score_cols) + n_cols - 1) // n_cols
    plt.figure(figsize=(15, n_rows * 4))

    for i, col in enumerate(score_cols, 1):
        plt.subplot(n_rows, n_cols, i)
        sns.histplot(data=df, x=col, kde=True)
        plt.title(f"Distribuição de {col}")
        plt.xticks(rotation=45)

    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, "feature_distributions.png"))


@create_and_save_plot
def plot_correlation_matrix(df, score_cols, images_dir):

    plt.figure(figsize=(12, 8))
    correlation_matrix = df[score_cols].corr()
    sns.heatmap(correlation_matrix, annot=True, cmap="coolwarm", center=0, fmt=".2f")
    plt.title("Matriz de Correlação entre Features")
    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, "correlation_matrix.png"))


@create_and_save_plot
def plot_execution_times(execution_times, images_dir):

    plt.figure(figsize=(12, 6))
    sns.barplot(x=list(execution_times.keys()), y=list(execution_times.values()))
    plt.title("Tempo de Execução dos Modelos")
    plt.xlabel("Modelo")
    plt.ylabel("Tempo (segundos)")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, "execution_times.png"))


@create_and_save_plot
def plot_metrics_comparison(metrics_df, images_dir):

    plt.figure(figsize=(12, 8))
    metrics_df.plot(kind="bar", width=0.8)
    plt.title("Comparação de Métricas entre Modelos")
    plt.xlabel("Modelos")
    plt.ylabel("Valor")
    plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, "metrics_comparison.png"))

    for metric in metrics_df.columns:
        plt.figure(figsize=(10, 6))
        sns.barplot(x=metrics_df.index, y=metrics_df[metric])
        plt.title(f"{metric} por Modelo")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(images_dir, f'{metric.lower().replace(" ", "_")}.png'))


@create_and_save_plot
def plot_confusion_matrices(trained_models, X_test, y_test, images_dir):

    n_models = len(trained_models) - 1
    n_cols = 3
    n_rows = (n_models + n_cols - 1) // n_cols

    fig, axes = plt.subplots(n_rows, n_cols, figsize=(20, 6 * n_rows))
    axes = axes.ravel()

    for idx, (name, model) in enumerate(trained_models.items()):
        if name == "CNN":
            continue

        y_pred = model.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)

        sns.heatmap(cm, annot=True, fmt="d", ax=axes[idx])
        axes[idx].set_title(f"Matriz de Confusão - {name}")
        axes[idx].set_xlabel("Previsto")
        axes[idx].set_ylabel("Real")

    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, "confusion_matrices.png"))


@create_and_save_plot
def plot_class_distribution(df, images_dir):

    if "classificacao" not in df.columns:
        raise ValueError("Coluna 'classificacao' não encontrada no DataFrame")

    plt.figure(figsize=(10, 6))
    df["classificacao"].value_counts().plot(kind="bar", color="skyblue")
    plt.title("Distribuição das Classes no Dataset")
    plt.xlabel("Classe")
    plt.ylabel("Quantidade")
    plt.xticks(rotation=45)
    plt.grid(True, axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, "class_distribution.png"))


@create_and_save_plot
def plot_learning_curves(model, X_train, y_train, model_name, images_dir):

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
    train_std = np.std(train_scores, axis=1)
    val_mean = np.mean(val_scores, axis=1)
    val_std = np.std(val_scores, axis=1)

    plt.figure(figsize=(10, 6))
    plt.plot(train_sizes, train_mean, label="Score de Treino", marker="o")
    plt.fill_between(
        train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.15
    )
    plt.plot(train_sizes, val_mean, label="Score de Validação", marker="o")
    plt.fill_between(train_sizes, val_mean - val_std, val_mean + val_std, alpha=0.15)

    plt.title(f"Curva de Aprendizado - {model_name}")
    plt.xlabel("Tamanho do Conjunto de Treino")
    plt.ylabel("F1-Score")
    plt.legend(loc="lower right")
    plt.grid(True)
    plt.savefig(
        os.path.join(
            images_dir, f'learning_curve_{model_name.lower().replace(" ", "_")}.png'
        )
    )


@create_and_save_plot
def plot_learning_curves_cnn(history, model_name, images_dir):

    plt.figure(figsize=(12, 4))

    plt.subplot(1, 2, 1)
    plt.plot(history.history["accuracy"], label="Treino")
    plt.plot(history.history["val_accuracy"], label="Validação")
    plt.title(f"Acurácia do Modelo - {model_name}")
    plt.xlabel("Época")
    plt.ylabel("Acurácia")
    plt.legend()
    plt.grid(True)

    plt.subplot(1, 2, 2)
    plt.plot(history.history["loss"], label="Treino")
    plt.plot(history.history["val_loss"], label="Validação")
    plt.title(f"Loss do Modelo - {model_name}")
    plt.xlabel("Época")
    plt.ylabel("Loss")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(os.path.join(images_dir, f"learning_curve_{model_name.lower()}.png"))


def plot_metrics_tables(results, metrics_df, images_dir):

    plt.figure(figsize=(15, len(results) * 0.5 + 1))
    plt.axis("off")

    headers = ["", "Melhores Parâmetros", "Score Treino", "Score Teste"]
    cell_data = []

    for model_name, row in results.iterrows():
        params = str(row.get("Melhores Parâmetros", "NaN"))
        train_score = f"{row.get('Score Treino', 'NaN'):.6f}"
        test_score = f"{row.get('Score Teste', 'NaN'):.6f}"
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

    plt.title("Resultados dos modelos:", pad=20)
    plt.savefig(
        os.path.join(images_dir, "model_results.png"),
        bbox_inches="tight",
        dpi=300,
        facecolor="black",
    )
    plt.close()

    plt.figure(figsize=(15, len(metrics_df) * 0.5 + 1))
    plt.axis("off")

    headers = ["", "Acurácia", "F1-Score", "Precisão", "Recall", "Média Harmônica"]
    cell_data = []

    for model_name, row in metrics_df.iterrows():
        cell_data.append(
            [
                model_name,
                f"{row['Acurácia']:.4f}",
                f"{row['F1-Score']:.4f}",
                f"{row['Precisão']:.4f}",
                f"{row['Recall']:.4f}",
                f"{row['Média Harmônica']:.4f}",
            ]
        )

    table = plt.table(
        cellText=cell_data,
        colLabels=headers,
        cellLoc="center",
        loc="center",
        colWidths=[0.2, 0.16, 0.16, 0.16, 0.16, 0.16],
    )

    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.2, 1.5)

    plt.title("Tabela de Métricas:", pad=20)
    plt.savefig(
        os.path.join(images_dir, "metrics_table.png"),
        bbox_inches="tight",
        dpi=300,
        facecolor="black",
    )
    plt.close()
