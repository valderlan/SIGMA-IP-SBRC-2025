import inspect
import logging
import os
import sys
from datetime import datetime
from typing import Optional

import pandas as pd
from sklearn.preprocessing import LabelEncoder

current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

from config.config import (
    SCORE_COLS,
    create_experiment_directory,
    get_pipeline_config,
    initialize_project,
)
from src.data_processing import (
    load_and_preprocess_data,
    prepare_data_for_training,
    save_label_encoder,
)
from src.evaluate import (
    evaluate_model_accuracy,
    evaluate_models,
    generate_classification_reports,
    save_evaluation_results,
)
from src.train import train_and_evaluate_models
from src.visualization import (
    plot_class_distribution,
    plot_confusion_matrices,
    plot_correlation_matrix,
    plot_execution_times,
    plot_feature_distributions,
    plot_feature_importance,
    plot_metrics_comparison,
    plot_metrics_tables,
    plot_roc_curves,
)


def setup_logging():
    """
    Setup logging configuration with file and console handlers
    """

    logs_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(logs_dir, f"pipeline_{timestamp}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_filename), logging.StreamHandler(sys.stdout)],
    )

    return logging.getLogger(__name__)


def generate_summary_report(
    metrics_df: pd.DataFrame,
    accuracy_df: pd.DataFrame,
    execution_times: dict,
    results_df: pd.DataFrame,
    experiment_dir: str,
    le: LabelEncoder,
    classification_reports: dict,
) -> Optional[str]:
    """
    Generate summary report with save verification.

    Args:
        metrics_df: Model metrics DataFrame
        accuracy_df: Model accuracy DataFrame
        execution_times: Execution times dictionary
        results_df: Training results DataFrame
        experiment_dir: Experiment directory

    Returns:
        str: Path to saved report or None if failed
    """
    try:
        report = []
        report.append("# Model Execution Report\n")
        report.append(f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append(f"Experiment Directory: {experiment_dir}\n")

        if (
            "models_s" in experiment_dir
            or "smote" in experiment_dir.lower()
            or "with_smote" in experiment_dir.lower()
        ):
            report.append("**Configuration**: WITH SMOTE\n")
        else:
            report.append("**Configuration**: WITHOUT SMOTE\n")

        class_labels = le.classes_
        report.append("## Class Mapping (LabelEncoder)\n")
        report.append(
            "The numerical classification used in the charts and forecasts corresponds to the following original labels.:\n"
        )

        report.append("| Numeric Code | Original Class Label |")
        report.append("|:---------------:|:-------------------------|")

        for i, label in enumerate(class_labels):
            report.append(f"| **{i}** | **{label}** |")

        report.append("\n## Model Performance Summary\n")

        accuracy_col = None
        possible_accuracy_cols = [
            "Balanced_Accuracy",
            "Accuracy (%)",
            "Acurácia (%)",
            "Accuracy",
            "Acurácia",
        ]

        for col in possible_accuracy_cols:
            if col in accuracy_df.columns:
                accuracy_col = col
                break

            if col in metrics_df.columns and accuracy_col is None:
                accuracy_col = col

        if accuracy_col and len(accuracy_df) > 0:
            try:

                if accuracy_col in accuracy_df.columns:
                    acc_series = accuracy_df[accuracy_col]
                else:
                    acc_series = metrics_df[accuracy_col] * 100

                top_models = acc_series.nlargest(3)

                report.append(
                    "### Top 3 Models by Performance (via Balanced Accuracy or Accuracy)\n"
                )
                for idx, (model_name, acc_value) in enumerate(top_models.items(), 1):

                    is_percent = "(%)" in accuracy_col
                    fmt = ".2f" if is_percent else ".4f"

                    if accuracy_col in ["Log_Loss", "Brier_Score"]:
                        report.append(
                            f"{idx}. **{model_name}**: {acc_value:{fmt}} (Lower is better)\n"
                        )
                    else:
                        unit = "%" if is_percent else ""
                        report.append(
                            f"{idx}. **{model_name}**: {acc_value:{fmt}}{unit}\n"
                        )

            except Exception as e:
                report.append("### Top Models\n")
                report.append(
                    "Could not generate ranking due to data format issues or missing column.\n"
                )
        else:
            report.append("### Models Trained\n")
            for model_name in accuracy_df.index:
                report.append(f"- **{model_name}**\n")

        report.append("\n## Optimized Hyperparameters by Model\n")
        for model_name, row in results_df.iterrows():
            hyperparams = row.get("Best Parameters", "N/A")
            report.append(f"### {model_name}\n")
            report.append(f"```\n{hyperparams}\n```\n")

        report.append("\n## Performance Metrics\n")

        metrics_cols = list(metrics_df.columns)
        if "Overfit_Gap" in metrics_cols:
            metrics_cols.remove("Overfit_Gap")
            metrics_cols.append("Overfit_Gap")

        report.append(
            metrics_df[metrics_cols].to_markdown(floatfmt=".4f")
        )  
        report.append("\n## Detailed Accuracy Results\n")
        report.append(accuracy_df.to_markdown(floatfmt=".4f"))

        report.append("\n## Training Execution Times\n")
        exec_df = pd.DataFrame.from_dict(
            execution_times, orient="index", columns=["Time (seconds)"]
        )
        exec_df = exec_df.sort_values("Time (seconds)", ascending=False)
        report.append(exec_df.to_markdown(floatfmt=".2f"))

        total_time = sum(execution_times.values())
        report.append(f"\n**Total Training Time**: {total_time:.2f} seconds\n")

        report.append("\n## Directory Structure\n")
        report.append(f"- **Experiment**: `{experiment_dir}`\n")
        report.append(
            f"- **Images (Plots)**: `{os.path.join(experiment_dir, 'images')}`\n"
        )
        report.append(
            f"- **Report (CSVs)**: `{os.path.join(experiment_dir, 'report')}`\n"
        )

        if (
            "models_s" in experiment_dir
            or "smote" in experiment_dir.lower()
            or "with_smote" in experiment_dir.lower()
        ):
            models_path = os.path.join(os.getcwd(), "data", "models_s")
        else:
            models_path = os.path.join(os.getcwd(), "data", "models")
        report.append(f"- **Models (Joblib/Keras)**: `{models_path}`\n")
        report.append("\n## Metrics by Class\n") # <-- Nova seção

        for model_name, report_str in classification_reports.items():
            report.append(f"### {model_name}\n")
            
            report.append("```\n")
            report.append(report_str)
            report.append("\n```\n")
            report.append("\n---\n")
            
        report.append("*Report generated automatically by ML Pipeline*\n")

        report_content = "\n".join(report)

        os.makedirs(experiment_dir, exist_ok=True)
        report_dir = os.path.join(experiment_dir, "report")
        os.makedirs(report_dir, exist_ok=True)

        report_path = os.path.join(report_dir, "summary_report.md")

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        return report_path

    except Exception as e:

        try:
            fallback_path = os.path.join(
                os.getcwd(),
                f"summary_report_emergency_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            )
            with open(fallback_path, "w", encoding="utf-8") as f:
                f.write("# Report Generation Failed\n\nError: " + str(e))
            return fallback_path
        except:
            return None


def create_safe_experiment_directory(experiment_name=None):
    """
    Create experiment directory using config.py functions
    """
    logger = logging.getLogger(__name__)

    try:

        project_dirs = initialize_project()
        logger.info(f"Project directories initialized: {list(project_dirs.keys())}")

        experiment_dir = create_experiment_directory(experiment_name)
        logger.info(f"Created experiment directory: {experiment_dir}")

        return experiment_dir

    except Exception as e:
        logger.error(f"Error creating experiment directory: {e}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if experiment_name:
            dir_name = f"{experiment_name}_{timestamp}"
        else:
            dir_name = f"experiment_{timestamp}"

        experiment_dir = os.path.join(os.getcwd(), "data", "experiments", dir_name)
        images_dir = os.path.join(experiment_dir, "images")
        report_dir = os.path.join(experiment_dir, "report")

        os.makedirs(experiment_dir, exist_ok=True)
        os.makedirs(images_dir, exist_ok=True)
        os.makedirs(report_dir, exist_ok=True)

        logger.info(f"Created fallback experiment directory: {experiment_dir}")
        return experiment_dir


def main_pipeline(use_smote=False, experiment_name=None):
    """
    Main pipeline that ensures files are saved properly
    """
    logger = logging.getLogger(__name__)
    logger.info("=" * 50)
    logger.info(
        f"STARTING MAIN PIPELINE - SMOTE: {'ENABLED' if use_smote else 'DISABLED'}"
    )
    logger.info("=" * 50)

    try:
        experiment_dir = create_safe_experiment_directory(experiment_name)
        images_dir = os.path.join(experiment_dir, "images")
        report_dir = os.path.join(experiment_dir, "report")
        os.makedirs(report_dir, exist_ok=True)

        if use_smote:
            models_dir = os.path.join("data", "models_s")
        else:
            models_dir = os.path.join("data", "models")

        logger.info(f"Experiment directory: {experiment_dir}")
        logger.info(f"Images directory: {images_dir}")
        logger.info(f"Report directory: {report_dir}")
        logger.info(f"Models directory: {models_dir}")

    except Exception as e:
        logger.error(f"Critical error creating directories: {e}")
        return {"success": False, "error": f"Critical error creating directories: {e}"}

    config = get_pipeline_config(use_smote)
    logger.info(f"Pipeline configuration: {config}")

    try:

        logger.info("Loading original dataset...")

        df = load_and_preprocess_data(config["data_file"])
        logger.info(f"Dataset loaded successfully. Shape: {df.shape}")

        logger.info("Generating feature visualizations...")

        try:
            plot_feature_distributions(df, SCORE_COLS, images_dir)
            plot_correlation_matrix(df, SCORE_COLS, images_dir)
            plot_class_distribution(df, images_dir)
            logger.info("Feature visualizations generated successfully")
        except Exception as e:
            logger.warning(f"Failed to generate some visualizations: {e}")
            pass

        logger.info("Preparing data for training...")

        X_train, X_test, y_train, y_test, le = prepare_data_for_training(df, SCORE_COLS)
        save_label_encoder(le, models_dir)

        logger.info(
            f"Data split completed - Train: {X_train.shape}, Test: {X_test.shape}"
        )

        logger.info("Starting model training...")

        try:
            sig = inspect.signature(train_and_evaluate_models)
            if "use_smote" in sig.parameters:
                results, execution_times, trained_models = train_and_evaluate_models(
                    X_train,
                    X_test,
                    y_train,
                    y_test,
                    models_dir,
                    images_dir,
                    use_smote=use_smote,
                )
            else:
                results, execution_times, trained_models = train_and_evaluate_models(
                    X_train, X_test, y_train, y_test, models_dir, images_dir
                )
            logger.info(
                f"Model training completed. Models trained: {list(trained_models.keys())}"
            )
        except Exception as e:
            logger.error(f"Training error: {e}")
            raise Exception(f"Training error: {e}")

        logger.info("Generating feature importance plots...")
        try:
            for model_name, model in trained_models.items():
                final_model = model
                if hasattr(model, "best_estimator_"):
                    final_model = model.best_estimator_

                if hasattr(final_model, "steps"):
                    final_model = final_model.steps[-1][1]

                if hasattr(final_model, "feature_importances_"):
                    plot_feature_importance(
                        final_model, model_name, SCORE_COLS, images_dir
                    )
                    logger.info(f"Feature importance plot generated for {model_name}")

        except Exception as e:
            logger.warning(f"Could not generate all feature importance plots: {e}")

        logger.info("Evaluating model performance...")

        logger.info("Generating per-class classification reports...")

        classification_reports = generate_classification_reports(
            trained_models, X_test, y_test, le
        )
        logger.info("Classification reports generated successfully")

        metrics_df = evaluate_models(trained_models, X_test, y_test)
        accuracy_df = evaluate_model_accuracy(trained_models, X_test, y_test, le)
        logger.info("Model evaluation completed successfully")

        logger.info("Saving evaluation results...")
        try:
            results_df = pd.DataFrame(results).T

            if "Best Parameters" in results_df.columns:
                results_df["Best Parameters"] = results_df["Best Parameters"].apply(
                    lambda x: str(x)
                )
                train_score_col = "Train Score"
                test_score_col = "Test Score"
            elif "Melhores Parâmetros" in results_df.columns:
                results_df["Best Parameters"] = results_df["Melhores Parâmetros"].apply(
                    lambda x: str(x)
                )
                results_df.drop("Melhores Parâmetros", axis=1, inplace=True)
                train_score_col = "Train Score"
                test_score_col = "Test Score"
            else:
                train_score_col = "Train Score"
                test_score_col = "Test Score"

            if (
                train_score_col in results_df.columns
                and test_score_col in results_df.columns
            ):

                overfit_gap = (
                    results_df[train_score_col] - results_df[test_score_col]
                ).abs()
                metrics_df["Overfit_Gap"] = overfit_gap
                logger.info("Overfit_Gap calculated and merged into metrics_df.")
            else:
                logger.warning(
                    "Could not calculate Overfit_Gap: Train/Test score columns not found."
                )

            results_csv_path = os.path.join(
                report_dir, "results_with_hyperparameters.csv"
            )
            results_df.to_csv(results_csv_path)
            logger.info(f"Results saved to: {results_csv_path}")

            save_evaluation_results(metrics_df, accuracy_df, report_dir)
            logger.info("Evaluation results saved successfully")

        except Exception as e:
            logger.warning(f"Failed to save some results: {e}")
            pass

        logger.info("Generating result visualizations...")

        try:
            plot_metrics_tables(results_df, metrics_df, images_dir)
            plot_execution_times(execution_times, images_dir)
            plot_metrics_comparison(metrics_df, images_dir)
            plot_confusion_matrices(trained_models, X_test, y_test, images_dir)
            plot_roc_curves(trained_models, X_test, y_test, le, images_dir)
            logger.info("Result visualizations generated successfully")
        except Exception as e:
            logger.warning(f"Failed to generate some result visualizations: {e}")
            pass

        logger.info("Generating summary report...")

        report_file = generate_summary_report(
            metrics_df,
            accuracy_df,
            execution_times,
            results_df,
            experiment_dir,
            le,
            classification_reports,
        )
        logger.info(f"Summary report generated: {report_file}")

        smote_status = (
            "WITH SMOTE (correctly applied)" if use_smote else "WITHOUT SMOTE"
        )
        success_message = (
            f"Pipeline completed successfully! ({smote_status})\n"
            f"- Directory: {experiment_dir}\n"
            f"- Report (CSVs and MD): {report_dir}\n"
            f"- Models: {models_dir}\n"
            f"- Charts: {images_dir}\n"
            f"- NO DATA LEAKAGE"
        )

        logger.info(success_message)

        return {
            "experiment_dir": experiment_dir,
            "metrics": metrics_df,
            "accuracy": accuracy_df,
            "classification_reports": classification_reports,
            "use_smote": use_smote,
            "report_file": report_file,
            "success": True,
            "top_models": accuracy_df.nlargest(
                3,
                (
                    "Accuracy (%)"
                    if "Accuracy (%)" in accuracy_df.columns
                    else "Acurácia (%)"
                ),
            ),
        }

    except Exception as e:
        error_msg = f"Error during execution: {str(e)}"
        logger.error(error_msg)

        return {
            "experiment_dir": experiment_dir,
            "error": str(e),
            "use_smote": use_smote,
            "success": False,
        }


def run_both_experiments():
    """
    Execute both experiments with robust error handling
    """
    logger = logging.getLogger(__name__)
    logger.info("STARTING BOTH EXPERIMENTS (WITH AND WITHOUT SMOTE)")

    results = {}

    logger.info("Running experiment WITHOUT SMOTE...")
    try:
        results["without_smote"] = main_pipeline(
            use_smote=False, experiment_name="experiment_WITHOUT_smote"
        )
        if results["without_smote"]["success"]:
            logger.info("Experiment WITHOUT SMOTE completed successfully")
        else:
            logger.error(
                f"Experiment WITHOUT SMOTE failed: {results['without_smote']['error']}"
            )
    except Exception as e:
        logger.error(f"Exception in experiment WITHOUT SMOTE: {e}")
        results["without_smote"] = {"success": False, "error": str(e)}

    logger.info("Running experiment WITH SMOTE...")
    try:
        results["with_smote"] = main_pipeline(
            use_smote=True, experiment_name="experiment_WITH_smote"
        )
        if results["with_smote"]["success"]:
            logger.info("Experiment WITH SMOTE completed successfully")
        else:
            logger.error(
                f"Experiment WITH SMOTE failed: {results['with_smote']['error']}"
            )
    except Exception as e:
        logger.error(f"Exception in experiment WITH SMOTE: {e}")
        results["with_smote"] = {"success": False, "error": str(e)}

    logger.info("BOTH EXPERIMENTS COMPLETED")
    return results


def run_single_experiment(use_smote=False):
    """
    Execute single experiment
    """
    logger = logging.getLogger(__name__)
    experiment_type = "WITH" if use_smote else "WITHOUT"
    logger.info(f"STARTING SINGLE EXPERIMENT {experiment_type} SMOTE")

    experiment_name = f"experiment_{'with' if use_smote else 'without'}_smote_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    result = main_pipeline(use_smote=use_smote, experiment_name=experiment_name)

    if result["success"]:
        logger.info(f"Single experiment {experiment_type} SMOTE completed successfully")
    else:
        logger.error(
            f"Single experiment {experiment_type} SMOTE failed: {result['error']}"
        )

    return result


if __name__ == "__main__":

    logger = setup_logging()
    logger.info("=" * 60)
    logger.info("MACHINE LEARNING PIPELINE STARTED")
    logger.info("=" * 60)

    try:
        project_dirs = initialize_project()
        logger.info(f"Project structure initialized: {list(project_dirs.keys())}")
    except Exception as e:
        logger.error(f"Error initializing project structure: {e}")

    dataset_path = "datasets/dataset_ip_norm.csv"
    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found: {dataset_path}")
        logger.error(
            "Please ensure the dataset file exists before running the pipeline"
        )
        sys.exit(1)

    logger.info(f"Dataset found: {dataset_path}")

    results = run_both_experiments()

    logger.info("=" * 60)
    logger.info("FINAL RESULTS SUMMARY")
    logger.info("=" * 60)

    for experiment_type, result in results.items():
        logger.info(
            f"{experiment_type.upper()}: {'SUCCESS' if result['success'] else 'FAILED'}"
        )
        if not result["success"]:
            logger.error(f"  Error: {result['error']}")
        else:
            logger.info(f"  Experiment directory: {result['experiment_dir']}")

    logger.info("=" * 60)
    logger.info("MACHINE LEARNING PIPELINE COMPLETED")
    logger.info("=" * 60)
