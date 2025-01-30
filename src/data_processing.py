import os

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from config.config import SCORE_COLS


def load_and_preprocess_data(file_path):

    print("Carregando e pré-processando dados...")
    df = pd.read_csv(file_path)
    print(f"Dimensões originais do dataset: {df.shape}")
    df = df.dropna()
    print(f"Dimensões após remover valores None: {df.shape}")
    return df


def normalize_scores(df):

    print("Normalizando scores...")
    missing_cols = [col for col in SCORE_COLS if col not in df.columns]
    if missing_cols:
        raise ValueError(
            f"As colunas a seguir estão ausentes no dataframe: {missing_cols}"
        )
    return df, SCORE_COLS


def prepare_data_for_training(df, score_cols):

    X = df[score_cols]
    y = df["classificacao"]

    le = LabelEncoder()
    y = le.fit_transform(y)
    print("\nClasses únicas:", le.classes_)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    print("\nDivisão dos dados:")
    print(f"Treino: {X_train.shape}")
    print(f"Teste: {X_test.shape}")

    return X_train, X_test, y_train, y_test, le


def save_label_encoder(le, models_dir):

    joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))
    print("LabelEncoder salvo com sucesso!")
    joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))
    print("LabelEncoder salvo com sucesso!")
