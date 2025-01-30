import json
import os

import pandas as pd
from sklearn.preprocessing import MinMaxScaler

from util.map_risk_level import map_risk_level


class FeatureNormalizer:
    def __init__(self, config_path="config.json"):
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
                scaler = MinMaxScaler(feature_range=(0, 1))
                normalized_values = scaler.fit_transform(
                    df[[feature]].clip(lower=min_val, upper=max_val)
                ).flatten()
                df_normalized[feature] = pd.Series(normalized_values, index=df.index)
        return df_normalized

    def carregar_pesos_salvos(self, pasta="weights", nome_arquivo="pesos_finais.json"):

        caminho_arquivo = os.path.join(pasta, nome_arquivo)
        if not os.path.exists(caminho_arquivo):
            raise FileNotFoundError(
                f"O arquivo de pesos '{caminho_arquivo}' não foi encontrado."
            )
        with open(caminho_arquivo, "r") as file:
            pesos = json.load(file)
        return pd.Series(pesos)

    def aplicar_pesos(self, df, pesos):

        df_normalized = self.normalize_with_defined_ranges(df)
        scores = pd.DataFrame()
        for feature in df_normalized.columns:
            if feature in pesos.index:
                scores[feature] = df_normalized[feature] * pesos[feature]
        scores["score_final"] = scores.sum(axis=1)
        return scores

    def aplicar_pesos_em_novo_dataset(self, dataset_path = None, output_path = None):

        if dataset_path is None:
            dataset_path = self.config["dataset_path"]
        if output_path is None:
            output_path = self.config["output_path"]
        
        #dataset_path = self.config["dataset_path"]
        #output_path = self.config["output_path"]

        df = pd.read_csv(dataset_path)

        if "risk_recommended_pulsedrive" in df.columns:
            df["risk_recommended_pulsedrive"] = df["risk_recommended_pulsedrive"].apply(
                map_risk_level
            )

        pesos = self.carregar_pesos_salvos()
        features_selecionadas = list(self.feature_ranges.keys())
        features_inversas = self.config.get("features_inversas", [])

        df_selected = df[features_selecionadas].copy()
        df_norm = self.normalize_with_defined_ranges(df_selected)

        for feature in features_inversas:
            if feature in df_norm.columns:
                df_norm[feature] = 1 - df_norm[feature]

        scores = self.aplicar_pesos(df_norm, pesos)

        if "ip" in df.columns:
            scores.insert(0, "ip", df["ip"])

        if "score_final" in scores.columns:
            scores.drop(columns=["score_final"], inplace=True)

        scores.to_csv(output_path, index=False)
        print(f"Dataset processado salvo em: {output_path}")
        return scores


if __name__ == "__main__":
    normalizer = FeatureNormalizer()

    normalizer.aplicar_pesos_em_novo_dataset()
