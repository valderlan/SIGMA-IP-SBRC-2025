import json
import os

import pandas as pd

from .util.map_risk_level import map_risk_level

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "Total2.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "datasets", "novo_dataset_com_pesos.csv")
WEIGHTS_PATH = os.path.join(BASE_DIR, "weights")


class FeatureNormalizer:
    def __init__(self, config_path=CONFIG_PATH):
        self.config = self.load_config(config_path)
        self.feature_ranges = self.config.get("feature_ranges", {})

    @staticmethod
    def load_config(config_path):
        if not os.path.exists(config_path):
            raise FileNotFoundError(
                f"O arquivo de configuração '{config_path}' não foi encontrado."
            )
        with open(config_path, "r") as file:
            return json.load(file)

    def normalize_with_defined_ranges(self, df):
        df_normalized = pd.DataFrame()
        for feature, (min_val, max_val) in self.feature_ranges.items():
            if feature in df.columns:

                clipped_values = df[feature].clip(lower=min_val, upper=max_val)

                range_size = max_val - min_val
                if range_size > 0:
                    normalized_values = (clipped_values - min_val) / range_size
                else:
                    normalized_values = clipped_values * 0

                df_normalized[feature] = normalized_values
        return df_normalized

    def carregar_pesos_salvos(self, pasta=WEIGHTS_PATH, nome_arquivo="final_weights.json"):
        caminho_arquivo = os.path.join(pasta, nome_arquivo)
        if not os.path.exists(caminho_arquivo):
            raise FileNotFoundError(
                f"O arquivo de pesos '{caminho_arquivo}' não foi encontrado."
            )
        with open(caminho_arquivo, "r") as file:
            pesos = json.load(file)
        return pd.Series(pesos)

    def aplicar_pesos(self, df, pesos):

        scores = pd.DataFrame()
        for feature in df.columns:
            if feature in pesos.index:
                scores[feature] = df[feature] * pesos[feature]
        scores["score_final"] = scores.sum(axis=1)
        return scores

    def aplicar_pesos_em_novo_dataset(self, dataset_path=DATASET_PATH, output_path=OUTPUT_PATH):
        if dataset_path is None:
            dataset_path = self.config["dataset_path"]
        if output_path is None:
            output_path = self.config["output_path"]

        df = pd.read_csv(dataset_path)

        if "risk_recommended_pulsedive" in df.columns:
            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].apply(
                map_risk_level
            )

        features_selecionadas = list(self.feature_ranges.keys())
        df_selected = df[features_selecionadas].copy()

        df_norm = self.normalize_with_defined_ranges(df_selected)

        base_name = os.path.splitext(os.path.basename(dataset_path))[0]
        normalized_path = os.path.join(BASE_DIR, "datasets", f"{base_name}_normalizado.csv")

        df_norm_to_save = df_norm.copy()
        if "ip_address" in df.columns:
            df_norm_to_save.insert(0, "ip_address", df["ip_address"])

        df_norm_to_save.to_csv(normalized_path, index=False)
        print(f"Dataset normalizado salvo em: {normalized_path}")

        features_inversas = self.config.get("features_inversas", [])
        for feature in features_inversas:
            if feature in df_norm.columns:
                df_norm[feature] = 1 - df_norm[feature]

        pesos = self.carregar_pesos_salvos()
        scores = pd.DataFrame()

        for feature in df_norm.columns:
            if feature in pesos:
                scores[feature] = df_norm[feature] * pesos[feature]

        if "ip_address" in df.columns:
            scores.insert(0, "ip_address", df["ip_address"])

        scores.to_csv(output_path, index=False)
        print(f"Dataset com pesos aplicados salvo em: {output_path}")

        return scores


if __name__ == "__main__":
    normalizer = FeatureNormalizer()
    normalizer.aplicar_pesos_em_novo_dataset()
