import logging
import os
import time

from feature_weight_calculator import calculate_final_weights
from ip_classification import classify_ips_and_generate_plots


def setup_logging(log_file="outputs/full_pipeline.log"):
    """Configures the logging system.

    Args:
        log_file (str): Path to the log file. Defaults to "outputs/full_pipeline.log".

    Returns:
        logging.Logger: Configured logger instance.
    """

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


def execute_full_pipeline(config_path="config.json", output_dir="outputs"):
    """Executes the full analysis pipeline:
    1. Calculates final weights.
    2. Classifies IPs and generates plots.

    Args:
        config_path (str): Path to the configuration file. Defaults to "config.json".
        output_dir (str): Directory to save the results. Defaults to "outputs".

    Returns:
        pd.DataFrame: Final result of the processing.

    Raises:
        Exception: If any phase of the pipeline fails.
    """

    logger = setup_logging()

    start_time = time.time()

    logger.info("=========================================================")
    logger.info("STARTING FULL ANALYSIS PIPELINE")
    logger.info("=========================================================")

    logger.info("\n\nPHASE 1: WEIGHT CALCULATION")
    logger.info("---------------------------------------------------------")

    try:
        weights = calculate_final_weights(
            config_path=config_path,
        output_dir="weights",
            output_file="final_weights.json",
        )
        logger.info("Phase 1 completed successfully: Weights calculated and saved.")
    except Exception as e:
        logger.error(f"Error during weight calculation: {str(e)}")
        raise

    logger.info("\n\nPHASE 2: IP CLASSIFICATION")
    logger.info("---------------------------------------------------------")

    try:
        result = classify_ips_and_generate_plots(
            config_path=config_path, output_dir=output_dir
        )
        logger.info(
            "Phase 2 completed successfully: IPs classified and plots generated."
        )
    except Exception as e:
        logger.error(f"Error during IP classification: {str(e)}")
        raise

    end_time = time.time()
    total_time = end_time - start_time

    logger.info("\n\n=========================================================")
    logger.info(f"PIPELINE COMPLETED IN {total_time:.2f} SECONDS")
    logger.info("=========================================================")
    logger.info(f"All results saved in directory: {os.path.abspath(output_dir)}")

    return result


if __name__ == "__main__":
    try:
        final_result = execute_full_pipeline()
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error during pipeline execution: {str(e)}")
        