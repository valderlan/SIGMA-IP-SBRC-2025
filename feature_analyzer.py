import json
import os

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from feature_normalizer import FeatureNormalizer
from util.map_risk_level import map_risk_level


class FeatureAnalyzer:
    def __init__(self, config_path="config.json"):
        self.normalizer = FeatureNormalizer(config_path)
        self.config = self.normalizer.config

    def calcular_score_composto(self, variancias, correlacoes, features_inversas):
        debug_df = pd.DataFrame(
            {
                "Feature": variancias["Feature"],
                "Variancia": variancias["Variância"],
                "Correlacao": correlacoes.set_index("Feature").loc[
                    variancias["Feature"], "Correlação_Média"
                ],
            }
        )

        debug_df["Score_Importância"] = (
            debug_df["Variancia"] + debug_df["Correlacao"]
        ) / 2

        debug_df["Tipo"] = [
            "Blacklist" if col not in features_inversas else "Invertida (Whitelist)"
            for col in debug_df["Feature"]
        ]

        print("\ncálculos do score de Importancia:")
        print(debug_df.to_string(index=False))

        return debug_df

    def calcular_pesos_normalizados(self, resultados):
        score_norm = (
            resultados["score_composto"]["Score_Importância"]
            / resultados["score_composto"]["Score_Importância"].sum()
        )

        pesos_combinados = pd.DataFrame(
            {
                "Feature": resultados["variancias"]["Feature"],
                "Peso_Final": score_norm,
                "Tipo": resultados["variancias"]["Tipo"],
            }
        ).sort_values("Peso_Final", ascending=False)

        print("\nPesos Finais Calculados:")
        print(pesos_combinados.to_string(index=False))

        return pesos_combinados

    def salvar_pesos_em_json(
        self, pesos_combinados, pasta="weights", nome_arquivo="pesos_finais.json"
    ):
        if not os.path.exists(pasta):
            os.makedirs(pasta)

        caminho_arquivo = os.path.join(pasta, nome_arquivo)
        pesos_dict = pesos_combinados.set_index("Feature")["Peso_Final"].to_dict()

        with open(caminho_arquivo, "w") as file:
            json.dump(pesos_dict, file, indent=4)

        print(f"Pesos finais salvos em: {caminho_arquivo}")

    def calcular_score_final(self, df_norm, pesos):

        scores = pd.DataFrame()

        for feature in df_norm.columns:
            if feature in pesos.index:
                peso = pesos.loc[feature, "Peso_Final"]
                scores[feature] = df_norm[feature] * peso

        scores["score_final"] = scores.sum(axis=1)

        scores["classificacao"] = pd.cut(
            scores["score_final"],
            bins=[-np.inf, 0.2, 0.4, np.inf],
            labels=["Whitelist", "Suspeito", "Blacklist"],
        )

        print("\nDistribuição das Classificações:")
        print(scores["classificacao"].value_counts())

        return scores

    def analisar_features(self):

        caminho_arquivo = self.config["input_file"]
        caminho_saida = self.config["output_file"]

        df = pd.read_csv(caminho_arquivo)
        df["risk_recommended_pulsedrive"] = df["risk_recommended_pulsedrive"].apply(
            map_risk_level
        )

        features_selecionadas = list(self.normalizer.feature_ranges.keys())
        features_inversas = self.config.get("features_inversas", [])

        df_selected = df[features_selecionadas].copy()
        df_norm = self.normalizer.normalize_with_defined_ranges(df_selected)

        for feature in features_inversas:
            df_norm[feature] = 1 - df_norm[feature]

        variancias = pd.DataFrame(
            {
                "Feature": df_norm.columns,
                "Variância": np.var(df_norm, axis=0),
                "Tipo": [
                    (
                        "Blacklist"
                        if col not in features_inversas
                        else "Invertida (Whitelist)"
                    )
                    for col in df_norm.columns
                ],
            }
        ).sort_values("Variância", ascending=False)

        print("\nAnálise por Variância:")
        print(variancias.to_string(index=False))

        corr_matrix = df_norm.corr()
        mean_corr = corr_matrix.abs().mean()
        correlacoes = pd.DataFrame(
            {
                "Feature": df_norm.columns,
                "Correlação_Média": mean_corr,
                "Tipo": [
                    (
                        "Blacklist"
                        if col not in features_inversas
                        else "Invertida (Whitelist)"
                    )
                    for col in df_norm.columns
                ],
            }
        ).sort_values("Correlação_Média", ascending=False)

        print("\nAnálise por Correlação Média:")
        print(correlacoes.to_string(index=False))

        plt.figure(figsize=(12, 10))
        sns.heatmap(corr_matrix, annot=True, fmt=".2f", cmap="coolwarm", center=0)
        plt.title("Matriz de Correlação das Features")
        plt.xticks(rotation=45, ha="right")
        plt.yticks(rotation=0)
        plt.tight_layout()

        grafico_path = os.path.join("outputs", "correlation_matrix.png")
        if not os.path.exists("outputs"):
            os.makedirs("outputs")
        plt.savefig(grafico_path)
        print(f"Gráfico da matriz de correlação salvo em: {grafico_path}")
        plt.close()

        score_composto = self.calcular_score_composto(
            variancias, correlacoes, features_inversas
        )

        resultados = {
            "variancias": variancias,
            "correlacoes": correlacoes,
            "score_composto": score_composto,
            "matriz_correlacao": corr_matrix,
        }

        pesos_combinados = self.calcular_pesos_normalizados(resultados)
        resultados["pesos_combinados"] = pesos_combinados

        self.salvar_pesos_em_json(pesos_combinados)

        scores_finais = self.calcular_score_final(
            df_norm, pesos_combinados.set_index("Feature")
        )
        scores_finais.insert(0, "ip", df["ip"])

        colunas_ordenadas = ["ip"] + features_selecionadas + ["classificacao"]
        output_df = scores_finais[colunas_ordenadas]
        output_df.to_csv(caminho_saida, index=False)

        return resultados, scores_finais

    def gerar_graficos_distribuicao(self, scores_finais, pasta="outputs"):

        if not os.path.exists(pasta):
            os.makedirs(pasta)

        plt.rcParams.update({
        'font.size': 26,
        'axes.labelsize': 26,
        'axes.titlesize': 26,
        'xtick.labelsize': 22,
        'ytick.labelsize': 22,
        'legend.fontsize': 24
        })
        
        scores_ordenados = np.sort(scores_finais["score_final"])
        quantidade = np.arange(1, len(scores_ordenados) + 1)

        plt.figure(figsize=(10, 7))
        plt.plot(quantidade, scores_ordenados, linewidth=2)
        #plt.title("Distribuição dos Scores Finais (Ordenados)")
        plt.xlabel("Quantidade (ordenada)")
        plt.ylabel("Score Final")
        plt.grid(True, alpha=0.3)

        z = np.polyfit(quantidade, scores_ordenados, 1)
        p = np.poly1d(z)
        plt.plot(quantidade, p(quantidade), "r--", alpha=0.8, label="Tendência Linear")
        plt.legend(loc='upper left')
        plt.tight_layout()

        caminho_grafico_linha = os.path.join(pasta, "distribuicao_scores_linha.png")
        plt.savefig(caminho_grafico_linha, bbox_inches='tight', dpi=300)
        plt.close()

        print(f"Gráfico de linha dos scores salvos em: {caminho_grafico_linha}")

        plt.figure(figsize=(10, 7))
        plt.hist(scores_finais["score_final"], bins=20, edgecolor="black")
        #plt.title("Histograma dos Scores Finais")
        plt.xlabel("Score Final")
        plt.ylabel("Frequência")
        plt.grid(True, alpha=0.3)
        plt.tight_layout()

        caminho_grafico_hist = os.path.join(pasta, "distribuicao_scores_histograma.png")
        plt.savefig(caminho_grafico_hist, bbox_inches='tight', dpi=300)
        plt.close()

        print(f"Histograma dos scores salvo em: {caminho_grafico_hist}")


if __name__ == "__main__":
    analyzer = FeatureAnalyzer()

    resultados, scores_finais = analyzer.analisar_features()

    analyzer.gerar_graficos_distribuicao(scores_finais)
