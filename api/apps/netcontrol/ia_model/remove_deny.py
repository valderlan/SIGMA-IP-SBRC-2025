import pandas as pd

input_file = "datasets/dataset_ip_norm.csv"


output_file = "datasets/dataset_ip_normm.csv"


amount_to_remove = 200


print(f"Lendo o arquivo de entrada: {input_file}...")

try:
    df = pd.read_csv(input_file)

    print("\nDistribuição original das classes:")
    print(df["classification"].value_counts())
    print("-" * 30)

    denylist_indices = df[df["classification"] == "denylist"].index

    if len(denylist_indices) < amount_to_remove:
        print(
            f"Aviso: Você solicitou a remoção de {amount_to_remove} registros, mas apenas {len(denylist_indices)} foram encontrados."
        )
        indices_to_drop = denylist_indices
    else:

        indices_to_drop = (
            df.loc[denylist_indices].sample(n=amount_to_remove, random_state=42).index
        )

    df_modified = df.drop(indices_to_drop)

    print(
        f"Removendo {len(indices_to_drop)} registros aleatórios da classe 'denylist'..."
    )

    df_modified.to_csv(output_file, index=False)

    print("\nDistribuição das classes no novo dataset:")
    print(df_modified["classification"].value_counts())
    print("-" * 30)

    print(f"Arquivo '{output_file}' gerado com sucesso!")

except FileNotFoundError:
    print(
        f"ERRO: O arquivo '{input_file}' não foi encontrado. Por favor, verifique o nome e o caminho."
    )
except Exception as e:
    print(f"Ocorreu um erro inesperado: {e}")
