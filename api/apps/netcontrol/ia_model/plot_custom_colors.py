import os
import sys

import pandas as pd
import plotly.graph_objects as go

# --- CONFIGURATION ---

BENCHMARK_DIR = "benchmark"
INPUT_CSV = os.path.join(BENCHMARK_DIR, "benchmark_prediction_results0.csv")
OUTPUT_IMAGE = os.path.join(BENCHMARK_DIR, "benchmark_prediction_chart_custom2.png")

# Define specific colors for each model here to ensure consistency across different charts.
# Keys must match the 'Model' column in the CSV exactly.
MODEL_COLORS = {
    "DT": "#6A4C93",  # Roxo
    "NN": "#2E86AB",  # Azul Petróleo
    "SVM": "#4EA8DE",  # Azul Claro
    "KNN": "#4CB944",  # Verde
    #"Extra Trees": "#8CB369",  # Verde Claro
    # "Classifier ip":  '#F4AC32',  # Amarelo
    "Voting": "#E76F51",  # Vermelho
    "RF": "#D64550",  # Vermelho Rosado
    #"AdaBoost": "#B83B89",  # Magenta Escuro
    "Stacking": "#7C3E66",  # Roxo Berinjela (AdaBoost)
    "CNN": "#1D53A3",  # Vermelho
}

# Color to use if a model in the CSV is NOT found in the dictionary above
DEFAULT_COLOR = "#CCCCCC"


def generate_chart_from_csv():
    # 1. Check if CSV exists
    if not os.path.exists(INPUT_CSV):
        print(f"[ERROR] File not found: {INPUT_CSV}")
        return

    # 2. Read Data
    print(f"Reading data from: {INPUT_CSV}")
    df_res = pd.read_csv(INPUT_CSV)

    # Sort by Mean_ms (ascending)
    # df_res = df_res.sort_values('Mean_ms')

    custom_order = [
        "Stacking",
        "Voting",
        #"AdaBoost",
        "CNN",
        "NN",
        "RF",
        "DT",
        #"Extra Trees",
        "KNN",
        "SVM",
    ]

    # Converte a coluna 'Model' para um tipo categórico ordenado
    df_res["Model"] = pd.Categorical(
        df_res["Model"], categories=custom_order, ordered=True
    )

    # Ordena baseada na lista acima
    df_res = df_res.sort_values("Model")

    # 3. Apply Color Mapping
    # Create a list of colors corresponding to the sorted rows
    bar_colors = []
    for model_name in df_res["Model"]:
        # Get color from dictionary, otherwise use default
        color = MODEL_COLORS.get(model_name, DEFAULT_COLOR)
        bar_colors.append(color)

    # 4. Build Chart
    fig = go.Figure(
        data=[
            go.Bar(
                x=df_res["Model"],
                y=df_res["Mean_ms"],
                error_y=dict(
                    type="data",
                    array=df_res["Error_Margin"],
                    visible=True,
                    color="black",
                    thickness=1.5,
                    width=6,
                ),
                marker=dict(color=bar_colors, line=dict(color="black", width=1)),
                # Text labels on bars
                text=df_res["Mean_ms"].apply(lambda x: f"{x:.2f} ms"),
                textposition="outside",
                textfont=dict(size=20, color="black"),
            )
        ]
    )

    # 5. Layout and Styling (No Title)
    fig.update_layout(
        xaxis_title="Modelos",
        yaxis_title="Tempo de Inferência (ms)",
        yaxis=dict(
            showgrid=True,
            gridcolor="LightGrey",
            # Add 15% headroom for text labels
            # range=[0, df_res['Mean_ms'].max() * 1.15]
            range=[0, 43],
            tickfont=dict(size=22),
            title=dict(font=dict(size=26)),
        ),
        xaxis=dict(
            tickangle=-45, tickfont=dict(size=22), title=dict(font=dict(size=26))
        ),
        template="plotly_white",
        # Margins: b=bottom, t=top, l=left, r=right
        margin=dict(b=120, t=40, l=80, r=40),
        font=dict(family="Arial, sans-serif", size=14, color="black"),
    )

    # 6. Save Image
    try:
        fig.write_image(OUTPUT_IMAGE, width=1200, height=800, scale=3)
        print(f"Chart successfully saved to: {OUTPUT_IMAGE}")
    except ValueError as e:
        print(f"\n[ERROR] Could not save PNG. Ensure 'kaleido' is installed.")
        print(f"Details: {e}")


if __name__ == "__main__":
    generate_chart_from_csv()
