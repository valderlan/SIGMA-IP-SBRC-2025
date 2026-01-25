import logging
import os
import pickle
import sys
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Diretório dos modelos
MODELS_DIR = "data/models_s"  # Para modelos sem SMOTE
# MODELS_DIR = "data/models_s"      # Para modelos com SMOTE

# Escolha o modelo a ser usado
MODEL_NAME = "Voting"  
# Opções disponíveis:
# - "Random Forest" 
# - "SVM"
# - "Neural Network" 
# - "Extra Trees"
# - "Decision Tree"
# - "KNN"
# - "CNN"
# --- NOVOS ENSEMBLES ---
# - "AdaBoost"
# - "Voting"
# - "Stacking"
SCALER_PARAMS_FILE = "scaler_params.pkl"


class IPClassificationPredictor:
    """
    Classe para predição de classificação de IP usando modelos pré-treinados
    Funciona com a estrutura do dataset e aplica a mesma normalização usada no treino.
    """

    def __init__(
        self, models_dir=MODELS_DIR, scaler_params_file=SCALER_PARAMS_FILE, model_name=MODEL_NAME
    ):
        """
        Inicializa o Preditor de Classificação de IP

        Args:
            models_dir (str): Diretório contendo modelos treinados
            scaler_params_file (str): Caminho para o arquivo de parâmetros do scaler
            model_name (str): Nome do modelo a ser usado.
        """
        self.models_dir = models_dir
        self.scaler_params_file = scaler_params_file
        self.model_name = model_name
        self.model = None
        self.label_encoder = None
        self.scalers = None
        self.scaler_columns = None
        self.feature_ranges = None


        self.available_models = {
            "Random Forest": "Random Forest_model.joblib",
            "SVM": "SVM_model.joblib", 
            "Neural Network": "Neural Network_model.joblib",
            "Extra Trees": "Extra Trees_model.joblib",
            "Decision Tree": "Decision Tree_model.joblib",
            "KNN": "KNN_model.joblib",
            "CNN": "CNN_model.keras",
            "AdaBoost": "AdaBoost_model.joblib",
            "Voting": "Voting_model.joblib",
            "Stacking": "Stacking_model.joblib",
        }

        self.risk_mapping = {
            "none": 1,
            "unknown": 2,
            "low": 3,
            "medium": 4,
            "high": 5,
            "critical": 6,
        }


        self.expected_input_columns = [
            "ip", 
            "abuseipdb_confidence_score",
            "abuseipdb_total_reports",
            "abuseipdb_num_distinct_users",
            'apivoid_risk_score',
            'apivoid_blacklists_detection_rate',
            "risk_recommended_pulsedive",
            "virustotal_reputation",
            "virustotal_harmless",
            "virustotal_malicious",
            "virustotal_undetected",
            "virustotal_suspicious",
        ]

        self.model_feature_columns = [
            "abuseipdb_confidence_score",
            "abuseipdb_total_reports",
            "abuseipdb_num_distinct_users",
            'apivoid_risk_score',
            'apivoid_blacklists_detection_rate',
            "risk_recommended_pulsedive",
            "virustotal_reputation",
            "virustotal_harmless",
            "virustotal_malicious",
            "virustotal_undetected",
            "virustotal_suspicious",
        ]

        self.logger = self._setup_logger()

        self._load_scaler_params()
        self._load_model_components()

    def _setup_logger(self):
        """Configura a configuração de logging"""
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = os.path.join(logs_dir, f"ip_prediction_{timestamp}.log")

        logger = logging.getLogger(f"ip_predictor_{timestamp}")
        logger.setLevel(logging.INFO)

        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        file_handler = logging.FileHandler(log_filename)
        console_handler = logging.StreamHandler(sys.stdout)

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def _load_scaler_params(self):
        """Carrega os parâmetros do scaler do treinamento"""
        if os.path.exists(self.scaler_params_file):
            try:
                with open(self.scaler_params_file, "rb") as f:
                    scaler_data = pickle.load(f)

                self.scalers = scaler_data["scalers"]
                self.scaler_columns = scaler_data["columns"]
                self.feature_ranges = scaler_data["feature_ranges"]

                self.logger.info(
                    f"Parâmetros do Scaler carregados de: {self.scaler_params_file}"
                )
                self.logger.info(f"Colunas do Scaler: {self.scaler_columns}")
            except Exception as e:
                self.logger.error(f"Erro ao carregar parâmetros do scaler: {e}")
                self.scalers = None
        else:
            self.logger.error(
                f"Arquivo de parâmetros do scaler não encontrado: {self.scaler_params_file}"
            )
            self.scalers = None

    def _load_model_components(self):
        """Carrega o modelo especificado e o Label Encoder"""
        try:
           
            if self.model_name not in self.available_models:
                available_names = list(self.available_models.keys())
                self.logger.error(f"Nome do modelo inválido: {self.model_name}")
                self.logger.error(f"Modelos disponíveis: {available_names}")
                return False

            
            model_filename = self.available_models[self.model_name]
            model_path = os.path.join(self.models_dir, model_filename)
            
            if os.path.exists(model_path):
                if self.model_name == "CNN":
                    
                    try:
                        import tensorflow as tf
                        self.model = tf.keras.models.load_model(model_path)
                        self.logger.info(f"Modelo CNN carregado: {model_path}")
                    except ImportError:
                        self.logger.error("TensorFlow não disponível. Não é possível carregar o modelo CNN.")
                        return False
                else:
                  
                    self.model = joblib.load(model_path)
                    self.logger.info(f"Modelo {self.model_name} carregado: {model_path}")
            else:
                self.logger.error(f"Modelo {self.model_name} não encontrado: {model_path}")
                return False

            
            label_encoder_path = os.path.join(self.models_dir, "label_encoder.joblib")
            if os.path.exists(label_encoder_path):
                self.label_encoder = joblib.load(label_encoder_path)
                self.logger.info(f"Label encoder carregado: {label_encoder_path}")
                self.logger.info(
                    f"Classes disponíveis: {list(self.label_encoder.classes_)}"
                )
            else:
                self.logger.error(f"Label encoder não encontrado: {label_encoder_path}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Erro ao carregar componentes do modelo: {e}")
            return False

    def _dict_to_dataframe(self, data_dict):
        """
        Converte dicionário para DataFrame

        Args:
            data_dict: Dicionário com dados de IP

        Returns:
            pd.DataFrame: DataFrame com os dados
        """


        if isinstance(data_dict, dict) and any(
            key in data_dict for key in ["ip", "abuseipdb_confidence_score"]
        ):
            return pd.DataFrame([data_dict])


        elif isinstance(data_dict, list):
            return pd.DataFrame(data_dict)

        elif isinstance(data_dict, dict):
            return pd.DataFrame(data_dict)

        else:
            raise ValueError("Formato de dicionário não suportado")

    def _validate_and_prepare_data(self, df):
        """
        Valida e prepara os dados para corresponder à estrutura de treinamento

        Args:
            df (pd.DataFrame): DataFrame de entrada

        Returns:
            pd.DataFrame: DataFrame com estrutura validada
        """
        self.logger.info(f"Colunas de entrada: {list(df.columns)}")

        missing_cols = set(self.expected_input_columns) - set(df.columns)

        if missing_cols:
            self.logger.error(f"Colunas obrigatórias ausentes: {missing_cols}")
            self.logger.info("Colunas esperadas (mesmas do treinamento):")
            for col in self.expected_input_columns:
                self.logger.info(f"  - {col}")

            raise ValueError(
                f"Colunas obrigatórias ausentes: {missing_cols}. A entrada deve corresponder à estrutura de treinamento."
            )

        df = df[self.expected_input_columns].copy()

        self.logger.info("Estrutura de dados validada - corresponde ao formato de treinamento")
        return df

    def _handle_missing_values(self, df):
        """
        Trata valores ausentes (mesma estratégia do pré-processamento de treinamento)

        Args:
            df (pd.DataFrame): DataFrame com possíveis valores ausentes

        Returns:
            pd.DataFrame: DataFrame com valores ausentes tratados
        """

        numerical_cols = [
            col
            for col in self.model_feature_columns
            if col != "risk_recommended_pulsedive"
        ]
        

        for col in numerical_cols:
            if col in df.columns:
                

                df[col] = pd.to_numeric(df[col], errors='coerce')
                

                if df[col].notna().sum() > 0:
                    median_val = df[col].median()

                    fill_val = median_val if pd.notna(median_val) else 0.0
                    df[col] = df[col].fillna(fill_val)
                    if pd.notna(median_val):
                         self.logger.info(
                            f"Preenchidos {df[col].isna().sum()} valores ausentes em {col} com mediana: {median_val}"
                        )
                else:
                    df[col] = df[col].fillna(0.0)
                    self.logger.warning(f"Coluna {col} estava toda vazia/NaN - preenchida com 0.0")

        if "risk_recommended_pulsedive" in df.columns:
            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].fillna(
                "medium"
            )
            self.logger.info(
                "Preenchidos valores ausentes de risk_recommended_pulsedive com 'medium'"
            )

        return df

    def _encode_categorical_columns(self, df):
        """
        Codifica colunas categóricas (mesmo que no pré-processamento de treinamento)

        Args:
            df (pd.DataFrame): DataFrame com colunas categóricas

        Returns:
            pd.DataFrame: DataFrame com colunas codificadas
        """
        if "risk_recommended_pulsedive" in df.columns:
            self.logger.info("Codificando a coluna risk_recommended_pulsedive")
            
            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].astype(str)

            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].map(
                self.risk_mapping
            )

            unmapped_count = df["risk_recommended_pulsedive"].isna().sum()
            if unmapped_count > 0:
                self.logger.warning(
                    f"Encontrados {unmapped_count} valores de risco não mapeados - preenchendo com 'unknown/medium' (2 ou 4)"
                )
                # O mapeamento original usa 2 para 'unknown' e 4 para 'medium'. Usamos 4 como default.
                df["risk_recommended_pulsedive"] = df[
                    "risk_recommended_pulsedive"
                ].fillna(4) 

            encoded_values = df["risk_recommended_pulsedive"].value_counts()
            self.logger.info(f"Valores codificados: {encoded_values.to_dict()}")

        return df

    def _normalize_features(self, df):
        """
        Normaliza as features usando os mesmos scalers do treinamento

        Args:
            df (pd.DataFrame): DataFrame com features para normalizar

        Returns:
            pd.DataFrame: DataFrame com features normalizadas
        """
        if self.scalers is None:
            raise ValueError("Parâmetros do Scaler não carregados. Não é possível normalizar as features.")

        self.logger.info("Aplicando normalização usando scalers de treinamento")

        for col in self.model_feature_columns:
            if col in df.columns and col in self.scalers:
                scaler_info = self.scalers[col]
                scaler = scaler_info["scaler"]

                values = df[col].astype(float).values.reshape(-1, 1) 
                df[col] = scaler.transform(values).flatten()

                self.logger.info(
                    f"Normalizado {col}: range [{df[col].min():.3f}, {df[col].max():.3f}]"
                )
            elif col not in self.scalers:
                self.logger.warning(f"Nenhum scaler encontrado para coluna: {col}")

        self.logger.info("Normalização de Features concluída")
        return df

    def preprocess_for_prediction(self, input_data):
        """
        Pré-processa os dados para predição (mesmo pipeline do treinamento)

        Args:
            input_data: Caminho do arquivo CSV, dicionário ou DataFrame

        Returns:
            pd.DataFrame: DataFrame processado pronto para predição
        """
        self.logger.info("Iniciando pré-processamento para predição...")

        if isinstance(input_data, str):
            if not os.path.exists(input_data):
                raise FileNotFoundError(f"Arquivo CSV não encontrado: {input_data}")
            df = pd.read_csv(input_data)
            self.logger.info(
                f"Dataset carregado do CSV: {df.shape[0]} linhas, {df.shape[1]} colunas"
            )

            if df.empty:
                raise ValueError("Arquivo CSV está vazio")

        elif isinstance(input_data, (dict, list)):
            df = self._dict_to_dataframe(input_data)
            self.logger.info(
                f"Dataset criado a partir do dicionário: {df.shape[0]} linhas, {df.shape[1]} colunas"
            )
        elif isinstance(input_data, pd.DataFrame):
            df = input_data.copy()
            self.logger.info(
                f"DataFrame recebido: {df.shape[0]} linhas, {df.shape[1]} colunas"
            )
        else:
            raise ValueError(
                "Tipo de entrada não suportado. Use caminho CSV, dicionário ou DataFrame."
            )

        df = self._validate_and_prepare_data(df)

        #df = self._handle_missing_values(df)

        df = self._encode_categorical_columns(df)

        df = self._normalize_features(df)

        self.logger.info(
            f"Pré-processamento concluído: {df.shape[0]} linhas, {df.shape[1]} colunas"
        )
        return df

    def predict_classification(self, input_data, output_file=None):
        """
        Prediz a classificação do IP

        Args:
            input_data: Caminho do arquivo CSV, dicionário ou DataFrame (deve corresponder à estrutura de treinamento)
            output_file (str, optional): Caminho para salvar os resultados em CSV

        Returns:
            dict: Dicionário com previsões para cada IP
        """
        self.logger.info("Iniciando predição de classificação de IP")

        if self.model is None or self.label_encoder is None:
            return {"error": "Modelo ou label encoder não foram carregados corretamente"}

        try:

            processed_df = self.preprocess_for_prediction(input_data)

            feature_columns = self.model_feature_columns

            features_df = processed_df[feature_columns]
            
            features_np = features_df.values

            self.logger.info(
                f"Fazendo previsões para {len(features_df)} IPs usando {len(feature_columns)} features"
            )


            if self.model_name == "CNN":

                features_reshaped = features_np.reshape(features_np.shape[0], features_np.shape[1], 1)
                prediction_probs = self.model.predict(features_reshaped, verbose=0)
                predictions = np.argmax(prediction_probs, axis=1)
                confidences = np.max(prediction_probs, axis=1)
            else:

                predictions = self.model.predict(features_df)
                
                if hasattr(self.model, "predict_proba"):
                    probabilities = self.model.predict_proba(features_df)
                    confidences = np.max(probabilities, axis=1)
                else:
                    confidences = [None] * len(predictions)

            predicted_labels = self.label_encoder.inverse_transform(predictions)

            results = {}

            for i in range(len(predicted_labels)):

                if "ip" in processed_df.columns: 
                    ip_key = processed_df.iloc[i]["ip"] 
                else:
                    ip_key = f"ip_{i+1}"

                results[ip_key] = {
                    "classification": predicted_labels[i],
                    "confidence": (
                        float(confidences[i]) if confidences[i] is not None else None
                    ),
                    "model_used": self.model_name,
                }

            self.logger.info(f"Previsões concluídas para {len(results)} IPs")

            prediction_counts = {}
            for result in results.values():
                label = result["classification"]
                prediction_counts[label] = prediction_counts.get(label, 0) + 1

            self.logger.info("Resumo da Previsão:")
            for label, count in prediction_counts.items():
                self.logger.info(f"  {label}: {count}")

            if output_file:
                results_df = processed_df.copy()
                results_df["predicted_classification"] = predicted_labels
                results_df["prediction_confidence"] = confidences
                results_df["model_used"] = self.model_name
                results_df["prediction_timestamp"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                results_df.to_csv(output_file, index=False)
                self.logger.info(f"Resultados salvos em: {output_file}")

            return results

        except Exception as e:
            self.logger.error(f"Erro durante a predição: {e}")
            return {"error": str(e)}


if __name__ == "__main__":
    
    # Opção 1: IP Único (deve ter a estrutura exata do dataset de treinamento)
    '''single_ip_data = {
        "ip": "192.168.1.100",
        "abuseipdb_confidence_score": 25,
        "abuseipdb_total_reports": 3,
        "abuseipdb_num_distinct_users": 2,
        "apivoid_risk_score": 60,
        "apivoid_blacklists_detection_rate": 0.05,
        "risk_recommended_pulsedive": "medium",
        "virustotal_reputation": 0,
        "virustotal_harmless": 45,
        "virustotal_malicious": 1,
        "virustotal_undetected": 25,
        "virustotal_suspicious": 0,
    }'''

    # Opção 2: Arquivo CSV (deve corresponder à estrutura de treinamento)
    csv_file_path = "consulta.csv"
    output_csv_path = "datasets/prediction_results.csv"

    # Inicializa o preditor com o modelo escolhido
    predictor = IPClassificationPredictor(MODELS_DIR, SCALER_PARAMS_FILE, MODEL_NAME)

    # Faz a predição
    # Para IP único:
    #results = predictor.predict_classification(single_ip_data)

    # Para arquivo CSV:
    # results = predictor.predict_classification(csv_file_path, output_csv_path)