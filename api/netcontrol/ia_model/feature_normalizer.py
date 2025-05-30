import json
import os

import pandas as pd

from .util.map_risk_level import map_risk_level

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
FINAL_WEIGHTS_PATH = os.path.join(BASE_DIR, 'weights', 'final_weights.json')

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
                # Aplica clipping para garantir que os valores estão dentro do range
                clipped_values = df[feature].clip(lower=min_val, upper=max_val)

                # Normaliza manualmente usando os ranges definidos, não os valores encontrados
                range_size = max_val - min_val
                if range_size > 0:  # Evita divisão por zero
                    normalized_values = (clipped_values - min_val) / range_size
                else:
                    normalized_values = clipped_values * 0  # Se range_size=0, retorna 0

                df_normalized[feature] = normalized_values
        return df_normalized

    def carregar_pesos_salvos(self, pasta="weights", nome_arquivo=FINAL_WEIGHTS_PATH):
        caminho_arquivo = os.path.join(pasta, nome_arquivo)
        if not os.path.exists(caminho_arquivo):
            raise FileNotFoundError(
                f"O arquivo de pesos '{caminho_arquivo}' não foi encontrado."
            )
        with open(caminho_arquivo, "r") as file:
            pesos = json.load(file)
        return pd.Series(pesos)

    def aplicar_pesos(self, df, pesos):
        # Não precisamos normalizar novamente aqui, já que o df já deve estar normalizado
        scores = pd.DataFrame()
        for feature in df.columns:
            if feature in pesos.index:
                scores[feature] = df[feature] * pesos[feature]
        scores["score_final"] = scores.sum(axis=1)
        return scores

    def aplicar_pesos_em_novo_dataset(self, dataset_path=None, output_path=None):
        if dataset_path is None:
            dataset_path = self.config["dataset_path"]
        if output_path is None:
            output_path = self.config["output_path"]

        # Carrega o dataset
        df = pd.read_csv(dataset_path)

        # 1. Categorização da coluna risk_recommended_pulsedive (primeira etapa)
        if "risk_recommended_pulsedive" in df.columns:
            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].apply(
                map_risk_level
            )

        # Seleciona as features que serão processadas
        features_selecionadas = list(self.feature_ranges.keys())
        df_selected = df[features_selecionadas].copy()
        
        # 2. Normalização usando os valores min e max de config.json
        df_norm = self.normalize_with_defined_ranges(df_selected)

        # Salva o dataset normalizado com nome do arquivo de entrada + normalizado.csv
        base_name = os.path.splitext(os.path.basename(dataset_path))[0]
        normalized_path = f"{base_name}_normalizado.csv"

        # Cria uma cópia para salvar com todas as colunas do dataset original
        df_norm_to_save = df_norm.copy()
        if "ip_address" in df.columns:
            df_norm_to_save.insert(0, "ip_address", df["ip_address"])

        df_norm_to_save.to_csv(normalized_path, index=False)
        print(f"Dataset normalizado salvo em: {normalized_path}")

        # 3. Inversão das features especificadas
        features_inversas = self.config.get("features_inversas", [])
        for feature in features_inversas:
            if feature in df_norm.columns:
                df_norm[feature] = 1 - df_norm[feature]

        # 4. Aplicação dos pesos e geração do arquivo final
        pesos = self.carregar_pesos_salvos()
        scores = pd.DataFrame()

        for feature in df_norm.columns:
            if feature in pesos:
                scores[feature] = df_norm[feature] * pesos[feature]

        # Adicionar coluna IP se existir
        if "ip_address" in df.columns:
            scores.insert(0, "ip_address", df["ip_address"])

        # Salvar o arquivo com pesos sem a coluna score_final
        scores.to_csv(output_path, index=False)
        print(f"Dataset com pesos aplicados salvo em: {output_path}")

        return scores


if __name__ == "__main__":
    normalizer = FeatureNormalizer()
    normalizer.aplicar_pesos_em_novo_dataset()
