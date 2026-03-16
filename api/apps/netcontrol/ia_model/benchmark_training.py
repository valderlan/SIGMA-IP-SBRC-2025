import pandas as pd
import numpy as np
import time
import os
import sys
import logging
import scipy.stats as stats
import plotly.graph_objects as go
import plotly.express as px
import warnings
from datetime import datetime
from src.data_processing import load_and_preprocess_data, prepare_data_for_training
from src.train import train_and_evaluate_models
from config.config import SCORE_COLS
import src.visualization as visualization_module

current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("benchmark_training")
warnings.filterwarnings("ignore")

def mock_plotting_functions():
    """
    Replaces plotting functions with empty functions to speed up the benchmark
    and avoid creating thousands of image files during the loop.
    """
    visualization_module.plot_learning_curves = lambda *args, **kwargs: None
    visualization_module.plot_learning_curves_cnn = lambda *args, **kwargs: None
    visualization_module.plot_confusion_matrices = lambda *args, **kwargs: None
    visualization_module.plot_roc_curves = lambda *args, **kwargs: None
    visualization_module.plot_feature_importance = lambda *args, **kwargs: None

def run_training_benchmark(n_repeats=100, dataset_path="datasets/dataset_ip_norm.csv"):
    """
    Executes the training time benchmark.
    """
    BENCHMARK_DIR = 'benchmark'
    if not os.path.exists(BENCHMARK_DIR):
        os.makedirs(BENCHMARK_DIR)
    
    logger.info("="*80)
    logger.info(f"STARTING TRAINING BENCHMARK")
    logger.info(f"Repetitions: {n_repeats}")
    logger.info(f"Dataset: {dataset_path}")
    logger.info("="*80)

    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found: {dataset_path}")
        return

    logger.info("Loading data...")
    df = load_and_preprocess_data(dataset_path)
    X_train, X_test, y_train, y_test, le = prepare_data_for_training(df, SCORE_COLS)

    temp_models_dir = os.path.join(BENCHMARK_DIR, "temp_models")
    temp_images_dir = os.path.join(BENCHMARK_DIR, "temp_images")
    os.makedirs(temp_models_dir, exist_ok=True)
    os.makedirs(temp_images_dir, exist_ok=True)


    mock_plotting_functions()

    all_times = {}


    logger.info(f"Starting loop of {n_repeats} repetitions...")
    
    total_start_time = time.time()

    for i in range(n_repeats):
        iter_start = time.time()

        try:
            logging.getLogger("training").setLevel(logging.ERROR)
            
            _, execution_times, _ = train_and_evaluate_models(
                X_train, X_test, y_train, y_test, 
                temp_models_dir, 
                temp_images_dir, 
                use_smote=True 
            )

            for model_name, duration in execution_times.items():
                if model_name not in all_times:
                    all_times[model_name] = []
                all_times[model_name].append(duration)
                
        except Exception as e:
            logger.error(f"Error in iteration {i+1}: {e}")
            continue
            
        iter_duration = time.time() - iter_start
        

        if (i + 1) % 1 == 0: 
            logger.info(f"Iteration {i+1}/{n_repeats} completed in {iter_duration:.2f}s")

    total_duration = time.time() - total_start_time
    logger.info(f"Benchmark completed in {total_duration:.2f} seconds.")

    stats_results = []
    
    for model_name, times in all_times.items():
        times_arr = np.array(times)
        mean_time = np.mean(times_arr)
        std_dev = np.std(times_arr, ddof=1)
        n = len(times_arr)
        
        if n > 1:
            ci = stats.t.interval(0.95, df=n-1, loc=mean_time, scale=std_dev/np.sqrt(n))
            error_margin = ci[1] - mean_time
        else:
            ci = (mean_time, mean_time)
            error_margin = 0.0

        stats_results.append({
            'Model': model_name,
            'Mean_Time_s': mean_time,
            'Error_Margin': error_margin,
            'Lower_CI': ci[0],
            'Upper_CI': ci[1],
            'Min_Time': np.min(times_arr),
            'Max_Time': np.max(times_arr),
            'Samples': n
        })

    save_plotly_chart(stats_results, BENCHMARK_DIR)

    save_markdown_table(stats_results, BENCHMARK_DIR)

def save_plotly_chart(results, output_dir):

    df_res = pd.DataFrame(results).sort_values('Mean_Time_s')
    

    base_palette = px.colors.qualitative.Prism
    max_val = df_res['Mean_Time_s'].max()
    
    colors = []
    for i, row in enumerate(df_res.itertuples()):
        val = row.Mean_Time_s

        if val == max_val:
            colors.append('red') 
        else:

            color_idx = i % len(base_palette)
            colors.append(base_palette[color_idx])


    fig = go.Figure(data=[
        go.Bar(
            x=df_res['Model'],
            y=df_res['Mean_Time_s'],
            error_y=dict(
                type='data',
                array=df_res['Error_Margin'],
                visible=True,
                color='black',
                thickness=1.5,
                width=6
            ),
            marker=dict(
                color=colors,  
                line=dict(color='black', width=1)
            ),
            text=df_res['Mean_Time_s'].apply(lambda x: f'{x:.2f}s'),
            textposition='outside',
            textfont=dict(size=12, color='black')
        )
    ])
    
    fig.update_layout(
        xaxis_title='Model',
        yaxis_title='Training Time (seconds)',
        yaxis=dict(
            showgrid=True, 
            gridcolor='LightGrey',
            range=[0, df_res['Mean_Time_s'].max() * 1.15] 
        ),
        xaxis=dict(
            tickangle=-45,
            tickfont=dict(size=14)
        ),
        template='plotly_white',
        margin=dict(b=120, t=100, l=80, r=40),
        width=1200, 
        height=800,
        font=dict(family="Arial, sans-serif", size=14, color="black")
    )
    
    png_path = os.path.join(output_dir, 'benchmark_training_chart_smote.png')

    fig.write_image(png_path, scale=2)
    logger.info(f"Chart saved to: {png_path}")
    

def save_markdown_table(results, output_dir):
    """
    Generates a Markdown table ready to be pasted into summary_report.md
    """
    df_res = pd.DataFrame(results).sort_values('Mean_Time_s')

    table_df = df_res[['Model', 'Mean_Time_s', 'Lower_CI', 'Upper_CI', 'Min_Time', 'Max_Time']].copy()
    table_df.columns = ['Model', 'Average Time (s)', 'Lower CI (95%)', 'Upper CI (95%)', 'Min (s)', 'Max (s)']
    
    for col in table_df.columns:
        if col != 'Model':
            table_df[col] = table_df[col].apply(lambda x: f"{x:.4f}")

    md_content = f"\n## Training Time Benchmark (100 Repetitions)\n\n"
    md_content += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    md_content += table_df.to_markdown(index=False)
    
    md_path = os.path.join(output_dir, 'training_benchmark_table_smote.md')
    
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md_content)
    
    logger.info(f"Markdown table saved to: {md_path}")

    csv_path = os.path.join(output_dir, 'training_benchmark_data_smote.csv')
    df_res.to_csv(csv_path, index=False)
    logger.info(f"Raw data saved to: {csv_path}")

if __name__ == "__main__":

    run_training_benchmark(n_repeats=100)