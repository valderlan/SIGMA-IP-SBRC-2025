import os

import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model

from config.config import SCORE_COLS


def predict_ip_classification(input_path, models_dir, model_name):
    """
    Prediz a classificação (blacklist, whitelist ou suspeito) para novos IPs
    usando o modelo especificado.

    Args:
        input_path (str): Caminho para o arquivo CSV com os novos dados
        models_dir (str): Diretório onde estão salvos os modelos treinados
        model_name (str): Nome do modelo a ser usado (ex: 'Random Forest', 'SVM', etc.)

    Returns:
        pd.DataFrame: DataFrame com as predições do modelo selecionado
    """

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Arquivo {input_path} não encontrado.")

    print("Carregando novos dados...")
    new_df = pd.read_csv(input_path)

    missing_cols = [col for col in SCORE_COLS if col not in new_df.columns]
    if missing_cols:
        raise KeyError(f"Features ausentes no arquivo: {missing_cols}")

    X_new = new_df[SCORE_COLS]

    print("Carregando LabelEncoder...")
    le = joblib.load(os.path.join(models_dir, "label_encoder.joblib"))

    if model_name == "CNN":
        model_file = "CNN_model.keras"
    else:
        model_file = f"{model_name}_model.joblib"

    model_path = os.path.join(models_dir, model_file)
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Modelo {model_file} não encontrado em {models_dir}")

    print(f"Predizendo com modelo {model_name}...")
    if model_name == "CNN":
        model = load_model(model_path)
        X_new_reshaped = X_new.values.reshape(X_new.shape[0], X_new.shape[1], 1)
        y_pred = model.predict(X_new_reshaped)
        y_pred = np.argmax(y_pred, axis=1)
    else:
        model = joblib.load(model_path)
        y_pred = model.predict(X_new)

    predictions = le.inverse_transform(y_pred)

    results_df = pd.DataFrame()
    if "ip" in new_df.columns:
        results_df["ip"] = new_df["ip"]
    results_df["classificacao"] = predictions
    results_df["modelo_utilizado"] = model_name

    return results_df


def get_available_models(models_dir):

    available_models = []
    for file in os.listdir(models_dir):
        if file.endswith("_model.joblib"):
            model_name = file.replace("_model.joblib", "")
            available_models.append(model_name)
        elif file == "CNN_model.keras":
            available_models.append("CNN")
    return available_models


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Prediz classificação para novos IPs")
    parser.add_argument(
        "input_file", type=str, help="datasets/teste.csv"
    )
    parser.add_argument(
        "models_dir", type=str, help="data/experiments/experiment_20250108_102855/models"
    )
    parser.add_argument("model_name", type=str, help="Random Forest")
    parser.add_argument(
        "--output", type=str, help="outputs"
    )

    args = parser.parse_args()

    try:

        available_models = get_available_models(args.models_dir)
        print(f"\nModelos disponíveis: {available_models}")

        if args.model_name not in available_models:
            raise ValueError(
                f"Modelo '{args.model_name}' não disponível. Escolha um dos modelos listados acima."
            )

        predictions_df = predict_ip_classification(
            args.input_file, args.models_dir, args.model_name
        )

        print("\nResultados das predições:")
        print(predictions_df)

        if args.output:
            predictions_df.to_csv(args.output, index=False)
            print(f"\nResultados salvos em: {args.output}")

    except Exception as e:
        print(f"Erro ao realizar predições: {str(e)}")
    except Exception as e:
        print(f"Erro ao realizar predições: {str(e)}")
