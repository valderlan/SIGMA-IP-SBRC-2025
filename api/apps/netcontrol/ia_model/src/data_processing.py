import os

import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


def load_and_preprocess_data(file_path):

    df = pd.read_csv(file_path)
    df = df.dropna()

    return df


def prepare_data_for_training(df, score_cols):

    X = df[score_cols]
    y = df["classification"]

    le = LabelEncoder()
    y = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    return X_train, X_test, y_train, y_test, le


def save_label_encoder(le, models_dir):

    joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))
    joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))
