import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
import os

def prepare_balanced_dataset(
    input_file="datasets/Total2_classified.csv",
    output_dir="datasets",
    test_size=0.2,
    random_state=42,
    apply_smote=True
):
    """
    Prepara dataset balanceado aplicando SMOTE CORRETAMENTE após train_test_split.
    
    Args:
        input_file (str): Caminho para o dataset original
        output_dir (str): Diretório para salvar os datasets processados
        test_size (float): Proporção do conjunto de teste
        random_state (int): Seed para reprodutibilidade
        apply_smote (bool): Se deve aplicar SMOTE ou não
    
    Returns:
        dict: Informações sobre os datasets criados
    """
    
    print("=== PREPARAÇÃO CORRETA DO DATASET ===")
    
    # 1. Carregar dados originais
    print(f"1. Carregando dataset original: {input_file}")
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Dataset não encontrado: {input_file}")
    
    dataset = pd.read_csv(input_file)
    print(f"   Dimensões originais: {dataset.shape}")
    
    # Verificar se há valores nulos
    if dataset.isnull().sum().sum() > 0:
        print("   Removendo valores nulos...")
        dataset = dataset.dropna()
        print(f"   Dimensões após limpeza: {dataset.shape}")
    
    # 2. Separar features e target
    print("2. Separando features e target...")
    
    # Identificar colunas que não são features
    non_feature_cols = ["classification", "ip_address"]
    feature_cols = [col for col in dataset.columns if col not in non_feature_cols]
    
    X = dataset[feature_cols]
    y = dataset["classification"]
    ip_info = dataset[["ip_address", "classification"]] if "ip_address" in dataset.columns else None
    
    print(f"   Features: {len(feature_cols)} colunas")
    print(f"   Distribuição original das classes:")
    print(y.value_counts().to_string())
    
    # 3. PRIMEIRO fazer train_test_split (SEM SMOTE)
    print("3. Dividindo em treino e teste (SEM aplicar SMOTE ainda)...")
    
    if ip_info is not None:
        # Manter informação dos IPs para rastreabilidade
        X_train_full, X_test_full, y_train, y_test = train_test_split(
            dataset[feature_cols + ["ip_address"]], 
            y, 
            test_size=test_size, 
            random_state=random_state, 
            stratify=y
        )
        
        # Separar IPs do conjunto de features
        X_train = X_train_full[feature_cols]
        X_test = X_test_full[feature_cols]
        train_ips = X_train_full["ip_address"]
        test_ips = X_test_full["ip_address"]
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        train_ips = None
        test_ips = None
    
    print(f"   Treino: {X_train.shape}")
    print(f"   Teste: {X_test.shape}")
    print(f"   Distribuição treino:")
    print(y_train.value_counts().to_string())
    print(f"   Distribuição teste:")
    print(y_test.value_counts().to_string())
    
    # 4. Aplicar SMOTE APENAS no conjunto de treino (se solicitado)
    os.makedirs(output_dir, exist_ok=True)
    
    if apply_smote:
        print("4. Aplicando SMOTE APENAS no conjunto de treino...")
        
        smote = SMOTE(random_state=random_state)
        X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
        
        print(f"   Treino balanceado: {X_train_balanced.shape}")
        print(f"   Distribuição após SMOTE:")
        print(pd.Series(y_train_balanced).value_counts().to_string())
        
        # Salvar dataset de treino balanceado
        train_balanced_df = pd.DataFrame(X_train_balanced, columns=feature_cols)
        train_balanced_df["classification"] = y_train_balanced
        
        # Adicionar IPs sintéticos de forma mais clara
        if train_ips is not None:
            original_count = len(y_train)
            synthetic_count = len(y_train_balanced) - original_count
            
            # IPs originais + IPs sintéticos claramente marcados
            all_ips = list(train_ips) + [f"SYNTHETIC_IP_{i+1}" for i in range(synthetic_count)]
            train_balanced_df["ip_address"] = all_ips
            
            # Reordenar colunas
            train_balanced_df = train_balanced_df[["ip_address"] + feature_cols + ["classification"]]
        
        train_file = os.path.join(output_dir, "train_with_smote.csv")
        train_balanced_df.to_csv(train_file, index=False)
        print(f"   Dataset de treino com SMOTE salvo: {train_file}")
        
    else:
        print("4. Mantendo dataset de treino original (sem SMOTE)...")
        X_train_balanced = X_train.copy()
        y_train_balanced = y_train.copy()
        
        # Salvar dataset de treino original
        train_df = pd.DataFrame(X_train_balanced, columns=feature_cols)
        train_df["classification"] = y_train_balanced
        
        if train_ips is not None:
            train_df["ip_address"] = train_ips.values
            train_df = train_df[["ip_address"] + feature_cols + ["classification"]]
        
        train_file = os.path.join(output_dir, "train_original.csv")
        train_df.to_csv(train_file, index=False)
        print(f"   Dataset de treino original salvo: {train_file}")
    
    # 5. Salvar conjunto de teste (SEMPRE intocado)
    print("5. Salvando conjunto de teste (intocado)...")
    
    test_df = pd.DataFrame(X_test, columns=feature_cols)
    test_df["classification"] = y_test
    
    if test_ips is not None:
        test_df["ip_address"] = test_ips.values
        test_df = test_df[["ip_address"] + feature_cols + ["classification"]]
    
    test_file = os.path.join(output_dir, "test_set.csv")
    test_df.to_csv(test_file, index=False)
    print(f"   Dataset de teste salvo: {test_file}")
    
    # 6. Criar dataset completo processado (original) para comparação
    print("6. Salvando dataset original processado...")
    original_file = os.path.join(output_dir, "original_processed.csv")
    dataset.to_csv(original_file, index=False)
    print(f"   Dataset original processado salvo: {original_file}")
    
    # 7. Retornar informações
    info = {
        "original_shape": dataset.shape,
        "train_shape": X_train_balanced.shape,
        "test_shape": X_test.shape,
        "feature_columns": feature_cols,
        "smote_applied": apply_smote,
        "files_created": {
            "train": train_file,
            "test": test_file,
            "original": original_file
        },
        "class_distribution": {
            "original": y.value_counts().to_dict(),
            "train_final": pd.Series(y_train_balanced).value_counts().to_dict(),
            "test": y_test.value_counts().to_dict()
        }
    }
    
    print("\n=== RESUMO ===")
    print(f"Dataset original: {info['original_shape']}")
    print(f"Treino final: {info['train_shape']}")
    print(f"Teste: {info['test_shape']}")
    print(f"SMOTE aplicado: {info['smote_applied']}")
    print(f"Arquivos criados: {len(info['files_created'])} arquivos")
    
    return info


def prepare_both_versions():
    """
    Prepara duas versões: com SMOTE e sem SMOTE para comparação.
    """
    print("=== PREPARANDO AMBAS AS VERSÕES (COM E SEM SMOTE) ===\n")
    
    # Versão com SMOTE
    print("VERSÃO COM SMOTE:")
    info_smote = prepare_balanced_dataset(
        input_file="datasets/Total2_classified.csv",
        output_dir="datasets/with_smote",
        apply_smote=True
    )
    
    print("\n" + "="*60 + "\n")
    
    # Versão sem SMOTE
    print("VERSÃO SEM SMOTE:")
    info_no_smote = prepare_balanced_dataset(
        input_file="datasets/Total2_classified.csv",
        output_dir="datasets/without_smote",
        apply_smote=False
    )
    
    return info_smote, info_no_smote


if __name__ == "__main__":
    # Executar preparação de ambas as versões
    info_smote, info_no_smote = prepare_both_versions()
    
    print("\n" + "="*60)
    print("PREPARAÇÃO CONCLUÍDA COM SUCESSO!")
    print("="*60)
    print("\nAgora você pode usar:")
    print("- datasets/with_smote/ para treinar com SMOTE")
    print("- datasets/without_smote/ para treinar sem SMOTE")
    print("- Mesmo conjunto de teste para ambas as versões")
    print("\nNÃO HÁ MAIS DATA LEAKAGE! ✅")