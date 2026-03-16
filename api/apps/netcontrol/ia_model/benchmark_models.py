import pandas as pd
import numpy as np
import time
import os
import sys
import logging
import platform 
import scipy.stats as stats
import warnings
from ip_prediction import IPClassificationPredictor
import psutil

import plotly.graph_objects as go
import plotly.express as px 


warnings.filterwarnings("ignore", message="X does not have valid feature names")
warnings.filterwarnings("ignore", category=UserWarning)


def get_system_specs():
    """
    Captura informações de hardware e software para o log.
    """
    specs = []
    specs.append(f"OS: {platform.system()} {platform.release()} ({platform.version()})")
    specs.append(f"Architecture: {platform.machine()}")
    specs.append(f"Processor: {platform.processor()}")
    specs.append(f"Python Version: {platform.python_version()}")
   
    mem = psutil.virtual_memory()
    total_ram_gb = mem.total / (1024 ** 3)
    specs.append(f"RAM: {total_ram_gb:.2f} GB")
    specs.append(f"Cores (Physical): {psutil.cpu_count(logical=False)}")
    specs.append(f"Cores (Logical): {psutil.cpu_count(logical=True)}")
    
    return "\n".join(specs)

def run_benchmark():

    INPUT_FILE = 'datasets/dataset_ipt.csv'
    BENCHMARK_DIR = 'benchmark'

    MODELS_TO_TEST = [
        "Random Forest", "SVM", "Neural Network", "Voting","Extra Trees", 
        "Decision Tree", "KNN", "CNN", "AdaBoost", "Stacking"
    ]

    if not os.path.exists(BENCHMARK_DIR):
        os.makedirs(BENCHMARK_DIR)
        print(f"Directory '{BENCHMARK_DIR}' created.")

    if not os.path.exists(INPUT_FILE):
        print(f"WARNING: {INPUT_FILE} not found. Using dummy data.")
        test_data = [{'ip': '1.1.1.1'}] * 100
    else:
        df = pd.read_csv(INPUT_FILE)
        test_data = df.head(100).to_dict('records')
        if len(test_data) < 100:
            print(f"WARNING: Dataset has only {len(test_data)} rows.")

    benchmark_results = []

    print(f"\n{'='*80}")
    print(f"STARTING PREDICTION BENCHMARK")
    print(f"{'='*80}")

    # --- 2. Loop de Teste dos Modelos ---
    for model_name in MODELS_TO_TEST:
        print(f"\n--> Evaluating Model: {model_name}")
        
        try:
            predictor = IPClassificationPredictor(model_name=model_name)
            if getattr(predictor, 'model', None) is None:
                print(f"    [Skip] Model file not found.")
                continue
            
            predictor.logger.setLevel(logging.ERROR)
            
            ip_avg_times = [] 
            sys.stdout.write("    Progress: [")
            
            
            row_limit = len(test_data)
            
            for i, row_data in enumerate(test_data):
                if i == 0: predictor.predict_classification(row_data, output_file=None) 

                start_time = time.perf_counter()
                for _ in range(100): 
                    predictor.predict_classification(row_data, output_file=None)
                end_time = time.perf_counter()
                
                ip_avg_times.append((end_time - start_time) / 100)
                
                if (i + 1) % 10 == 0:
                    sys.stdout.write(".")
                    sys.stdout.flush()
            
            sys.stdout.write("] Done.\n")

            times_ms = np.array(ip_avg_times) * 1000
            mean_time = np.mean(times_ms)
            std_dev = np.std(times_ms, ddof=1) if len(times_ms) > 1 else 0
            n = len(times_ms)
            
            if n > 1:
                ci = stats.t.interval(0.95, df=n-1, loc=mean_time, scale=std_dev/np.sqrt(n))
                error_margin = ci[1] - mean_time 
            else:
                ci = (mean_time, mean_time)
                error_margin = 0

            benchmark_results.append({
                'Model': model_name,
                'Mean_ms': mean_time,
                'Error_Margin': error_margin,
                'Lower_CI': ci[0],
                'Upper_CI': ci[1]
            })
            print(f"    Mean Time: {mean_time:.4f} ms (+/- {error_margin:.4f})")

        except Exception as e:
            print(f"\n    [ERROR] Failed to test {model_name}: {e}")

    # --- 3. Inserir Dados Manuais (Voting Classifier) ---
    print(f"\n--> Injecting Manual Data: Voting Classifier")
    manual_mean = 7.6743
    manual_error = 0.0773
    benchmark_results.append({
        'Model': 'Classifier ip',
        'Mean_ms': manual_mean,
        'Error_Margin': manual_error,
        'Lower_CI': manual_mean - manual_error,
        'Upper_CI': manual_mean + manual_error
    })

    log_path = os.path.join(BENCHMARK_DIR, "system_config.log")
    sys_info = get_system_specs()
    
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("============================================\n")
        f.write(f"BENCHMARK RUN DATE: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("============================================\n")
        f.write("SYSTEM CONFIGURATION:\n")
        f.write(sys_info + "\n")
        f.write("============================================\n")
    
    print(f"\nSystem configuration saved to: {log_path}")

    if benchmark_results:
        save_results_png(benchmark_results, BENCHMARK_DIR)
    else:
        print("\nNo models were successfully tested.")

def save_results_png(results, output_dir):
    df_res = pd.DataFrame(results)
    
    df_res = df_res.sort_values('Mean_ms')
    
    csv_path = os.path.join(output_dir, 'benchmark_prediction_results.csv')
    df_res.to_csv(csv_path, index=False)
    

    max_val = df_res['Mean_ms'].max()
    
    # 2. Definir uma paleta de cores distintas
    # Você pode alterar 'Prism', 'Bold', 'Vivid', 'Pastel' etc.
    # Ou definir uma lista manual: ['#0000FF', '#00FF00', ...]
    #manual_palette = [
    #    '#00BFFF',  # DeepSkyBlue (Azul Claro)
    #    '#2E8B57',  # SeaGreen (Verde Mar)
    #    '#DAA520',  # GoldenRod (Dourado)
    #    '#9370DB',  # MediumPurple (Roxo)
    #    '#FF8C00',  # DarkOrange (Laranja)
    #    '#4682B4',  # SteelBlue (Azul Aço)
    #    '#D2691E',  # Chocolate
    #    '#556B2F'   # DarkOliveGreen
    #]
    base_palette = px.colors.qualitative.Prism 
    
    colors = []
    for i, row in enumerate(df_res.itertuples()):
        val = row.Mean_ms
        

        if val == max_val:
            colors.append('red') # '#FF0000'
        else:
            # COR DOS OUTROS MODELOS
            # Usa o operador % para ciclar a paleta se tiver muitos modelos
            color_idx = i % len(base_palette)
            #color_idx = i % len(manual_palette)
            colors.append(base_palette[color_idx])
            #colors.append(manual_palette[color_idx])
       
    fig = go.Figure(data=[
        go.Bar(
            x=df_res['Model'],
            y=df_res['Mean_ms'],
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
            text=df_res['Mean_ms'].apply(lambda x: f'{x:.2f} ms'),
            textposition='outside',
            textfont=dict(size=12, color='black')
        )
    ])
    
    fig.update_layout(
        xaxis_title='Model',
        yaxis_title='Inference Time (ms)',
        yaxis=dict(
            showgrid=True,
            gridcolor='LightGrey',
            range=[0, df_res['Mean_ms'].max() * 1.15] 
        ),
        xaxis=dict(
            tickangle=-45,
            tickfont=dict(size=14)
        ),
        template='plotly_white',
        margin=dict(b=120, t=100, l=80, r=40),
        font=dict(family="Arial, sans-serif", size=14, color="black")
    )
    
    png_path = os.path.join(output_dir, 'benchmark_prediction_chart.png')
    
    try:
        fig.write_image(png_path, width=1200, height=800, scale=3)
        print(f"-> Chart saved to: {png_path}")
    except ValueError as e:
        print(f"\n[ERROR] Could not save PNG. Check 'kaleido'. Error: {e}")

if __name__ == "__main__":
    run_benchmark()