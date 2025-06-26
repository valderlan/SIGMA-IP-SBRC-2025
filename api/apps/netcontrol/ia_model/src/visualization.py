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

# Configuração global de cores
plt.rcParams["axes.prop_cycle"] = plt.cycler(
    color=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"]
)  # Azul, Laranja, Verde, Vermelho
plt.rcParams["lines.linewidth"] = 2  # Espessura das linhas
plt.rcParams["axes.grid"] = True  # Exibir grade
plt.rcParams["grid.alpha"] = 0.3  # Transparência da grade

plt.rcParams["figure.max_open_warning"] = 0
plt.style.use("dark_background")
sns.set_style("darkgrid")
sns.set_palette("Set2")


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
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, "correlation_matrix.png"),
        bbox_inches="tight",
        transparent=True,
    )


@create_and_save_plot
def plot_execution_times(execution_times, images_dir):

    plt.figure(figsize=(12, 6))
    sns.barplot(
        x=list(execution_times.keys()),
        y=list(execution_times.values()),
        color="#0D47A1",
    )
    # plt.title("Tempo de Execução dos Modelos", fontsize=18)
    plt.xlabel("Modelo", fontsize=18)
    plt.ylabel("Tempo (segundos)", fontsize=18)
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

    # Remove a coluna "Média Harmônica" do DataFrame
    if "Média Harmônica" in metrics_df.columns:
        metrics_df = metrics_df.drop(columns=["Média Harmônica"])

    colors = [
        "blue",
        "orange",
        "darkgreen",
        "dimgray",
    ]  # Ajustar cores conforme o número de métricas
    model_labels = [
        "Random Forest",
        "SVM",
        "Rede Neural",
        "Extra Trees",
        "Árvore de Decisão",
        "KNN",
        "CNN",
    ]  # Novos nomes para os modelos

    plt.rc("font", size=18)
    plt.rc("axes", titlesize=12)
    plt.rc("axes", labelsize=12)
    plt.rc("xtick", labelsize=10)
    plt.rc("ytick", labelsize=10)
    plt.rc("legend", fontsize=8)
    plt.figure(figsize=(20, 16))

    metrics_df.plot(kind="bar", width=0.8, color=colors)
    plt.xlabel("Modelos", fontsize=14)
    plt.ylabel("Valor", fontsize=14)
    plt.xticks(
        ticks=range(len(metrics_df.index)),
        labels=model_labels,
        rotation=45,
        fontsize=12,
    )  # Ajuste direto no gráfico
    plt.legend(title="Métricas", bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, "metrics_comparison.png"),
        bbox_inches="tight",
        transparent=True,
    )

    # Gera gráficos individuais para cada métrica
    for metric in metrics_df.columns:
        plt.figure(figsize=(10, 6))
        sns.barplot(x=metrics_df.index, y=metrics_df[metric], color="#0D47A1")
        plt.xlabel("Modelos", fontsize=16)
        plt.ylabel(metric, fontsize=16)
        plt.xticks(
            ticks=range(len(metrics_df.index)),
            labels=model_labels,
            rotation=45,
            fontsize=12,
        )  # Ajuste direto no gráfico
        plt.tight_layout()
        plt.savefig(
            os.path.join(images_dir, f'{metric.lower().replace(" ", "_")}.png'),
            bbox_inches="tight",
            transparent=True,
        )

    """#colors = ["blue", "orange", "darkgreen", "dimgray", "purple"]
    filtered_metrics_df = metrics_df.drop(columns=["Média Harmônica"], errors="ignore")

    colors = ["blue", "orange", "darkgreen", "dimgray", "purple"][:len(filtered_metrics_df.columns)]

    plt.rc("font", size=18)
    plt.rc("axes", titlesize=12)
    plt.rc("axes", labelsize=12)
    plt.rc("xtick", labelsize=10)
    plt.rc("ytick", labelsize=10)
    plt.rc("legend", fontsize=8)
    plt.figure(figsize=(24, 18))

    metrics_df.plot(kind="bar", width=0.8, color=colors)
    # plt.title("Comparação de Métricas entre Modelos", fontsize=18)
    plt.xlabel("Modelos", fontsize=14)
    plt.ylabel("Valor", fontsize=14)
    plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.tight_layout(pad=0.5)
    plt.savefig(
        os.path.join(images_dir, "metrics_comparison.png"),
        bbox_inches="tight",
        transparent=True,
    )

    for metric in filtered_metrics_df.columns: #metrics_df.columns:
        plt.figure(figsize=(10, 6))
        sns.barplot(x=filtered_metrics_df.index, y=filtered_metrics_df[metric], color="#0D47A1")
        #sns.barplot(x=metrics_df.index, y=metrics_df[metric], color="#0D47A1")
        # plt.title(f"{metric} por Modelo", fontsize=18)
        plt.xlabel("Modelos", fontsize=16)
        plt.ylabel(metric, fontsize=16)
        plt.xticks(rotation=45, fontsize=16)
        plt.yticks(fontsize=16)
        plt.tight_layout()
        plt.savefig(
            os.path.join(images_dir, f'{metric.lower().replace(" ", "_")}.png'),
            bbox_inches="tight",
            transparent=True,
        )"""


@create_and_save_plot
def plot_confusion_matrices(trained_models, X_test, y_test, images_dir):

    for name, model in trained_models.items():
        if name == "CNN":
            # Preparar os dados para CNN
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred, axis=1)
        else:
            # Previsões para outros modelos
            y_pred = model.predict(X_test)

        # Gerar matriz de confusão
        cm = confusion_matrix(y_test, y_pred)

        # Criar gráfico da matriz de confusão
        fig, ax = plt.subplots(figsize=(6, 6))  # Tamanho padrão para todas as matrizes
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            ax=ax,
            annot_kws={"size": 18},
            cbar_kws={"label": "Escala", "shrink": 1.0},
        )
        # ax.set_title(f"Matriz de Confusão - {name}", fontsize=18)
        ax.set_ylabel("Real", fontsize=18)
        ax.set_xlabel("Previsto", fontsize=18)

        ax.set_xticklabels(ax.get_xticklabels(), fontsize=16)
        ax.set_yticklabels(ax.get_yticklabels(), fontsize=16)

        # Salvar a imagem com o nome do modelo
        file_name = f"confusion_matrix_{name.lower().replace(' ', '_')}.png"
        plt.tight_layout(pad=0.5)
        plt.savefig(
            os.path.join(images_dir, file_name),
            bbox_inches="tight",
            transparent=True,
        )
        plt.close(fig)
        print(f"Imagem salva em: {os.path.join(images_dir, file_name)}")


@create_and_save_plot
def plot_class_distribution(df, images_dir):

    if "classification" not in df.columns:
        raise ValueError("Coluna 'classificacao' não encontrada no DataFrame")

    plt.figure(figsize=(10, 6))
    df["classification"].value_counts().plot(kind="bar", color="#0D47A1")
    # plt.title("Distribuição das Classes no Dataset", fontsize=18)
    plt.xlabel("Classe", fontsize=16)
    plt.ylabel("Quantidade", fontsize=16)
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
    # train_std = np.std(train_scores, axis=1)
    val_mean = np.mean(val_scores, axis=1)
    # val_std = np.std(val_scores, axis=1)

    plt.figure(figsize=(10, 6))
    plt.plot(train_sizes, train_mean, label="Score de Treino", color="blue", marker="o")
    # plt.fill_between(
    #    train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.15
    # )
    plt.plot(train_sizes, val_mean, label="Score de Validação", color="red", marker="o")
    # plt.fill_between(train_sizes, val_mean - val_std, val_mean + val_std, alpha=0.15)

    # plt.title(f"Curva de Aprendizado - {model_name}", fontsize=18)
    plt.xlabel("Tamanho do Conjunto de Treino", fontsize=16)
    plt.ylabel("F1-Score", fontsize=16)
    # plt.legend(loc="lower right")
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
    train_sizes = np.linspace(0.1, 1.0, len(history.history["accuracy"]))
    train_scores = history.history["accuracy"]
    val_scores = history.history["val_accuracy"]

    plt.figure(figsize=(10, 6))
    plt.plot(
        train_sizes, train_scores, label="Score de Treino", color="blue", marker="o"
    )
    plt.plot(
        train_sizes, val_scores, label="Score de Validação", color="red", marker="o"
    )
    # plt.fill_between(
    #    train_sizes,
    #    np.array(train_scores) - 0.05,
    #    np.array(train_scores) + 0.05,
    #    color="blue",
    #    alpha=0.2,
    # )
    # plt.fill_between(
    #    train_sizes,
    #    np.array(val_scores) - 0.05,
    #    np.array(val_scores) + 0.05,
    #    color="red",
    #    alpha=0.2,
    # )

    # plt.title(f"Curva de Aprendizado - {model_name}", fontsize=18)
    plt.xlabel("Proporção do Conjunto de Treino", fontsize=16)
    plt.ylabel("Acurácia", fontsize=16)
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
