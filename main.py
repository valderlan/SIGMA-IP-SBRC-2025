import os

import pandas as pd

from config.config import SCORE_COLS
from src.data_processing import (
    load_and_preprocess_data,
    normalize_scores,
    prepare_data_for_training,
    save_label_encoder,
)
from src.evaluate import (
    evaluate_model_accuracy,
    evaluate_models,
    save_evaluation_results,
)
from src.train import train_and_evaluate_models_with_balancing
from src.visualization import (
    plot_class_distribution,
    plot_confusion_matrices,
    plot_correlation_matrix,
    plot_execution_times,
    plot_feature_distributions,
    plot_metrics_comparison,
    plot_metrics_tables,
)
from util.utils import (
    create_experiment_directory,
    generate_summary_report,
    log_execution_info,
    save_experiment_config,
)


def main():

    experiment_dir = create_experiment_directory()
    images_dir = os.path.join(experiment_dir, "images")
    models_dir = os.path.join(experiment_dir, "models")

    config = {
        "data_file": "datasets/balanced_resultado_cal_w.csv",
        "test_size": 0.2,
        "random_state": 42,
        "score_cols": SCORE_COLS,
    }
    save_experiment_config(config, experiment_dir)

    log_execution_info("Iniciando pipeline de treinamento", experiment_dir)

    try:

        df = load_and_preprocess_data(config["data_file"])
        df_normalized, score_cols = normalize_scores(df)

        log_execution_info("Gerando visualizações das features...", experiment_dir)
        plot_feature_distributions(df_normalized, score_cols, images_dir)
        plot_correlation_matrix(df_normalized, score_cols, images_dir)
        plot_class_distribution(df_normalized, images_dir)

        log_execution_info("Preparando dados para treinamento...", experiment_dir)
        X_train, X_test, y_train, y_test, le = prepare_data_for_training(
            df_normalized, score_cols
        )
        save_label_encoder(le, models_dir)

        log_execution_info("Iniciando treinamento dos modelos...", experiment_dir)
        results, execution_times, trained_models = (
            train_and_evaluate_models_with_balancing(
                X_train, X_test, y_train, y_test, models_dir, images_dir
            )
        )

        log_execution_info("Avaliando performance dos modelos...", experiment_dir)
        metrics_df = evaluate_models(trained_models, X_test, y_test)

        log_execution_info("Gerando visualizações dos resultados...", experiment_dir)

        results_df = pd.DataFrame(results).T
        plot_metrics_tables(results_df, metrics_df, images_dir)

        plot_execution_times(execution_times, images_dir)
        plot_metrics_comparison(metrics_df, images_dir)
        plot_confusion_matrices(trained_models, X_test, y_test, images_dir)

        log_execution_info("Calculando métricas finais...", experiment_dir)
        accuracy_df = evaluate_model_accuracy(trained_models, X_test, y_test, le)

        save_evaluation_results(metrics_df, accuracy_df, models_dir)
        report_file = generate_summary_report(
            metrics_df, accuracy_df, execution_times, experiment_dir
        )

        log_execution_info(
            f"Pipeline concluído com sucesso!\n"
            f"- Relatório final: {report_file}\n"
            f"- Visualizações: {images_dir}\n"
            f"- Modelos salvos: {models_dir}",
            experiment_dir,
        )

    except Exception as e:
        log_execution_info(f"Erro durante a execução: {str(e)}", experiment_dir)
        raise


if __name__ == "__main__":
    main()
