import logging
import os
import pickle
import sys
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

# Diretório atual e path
current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Configurações Globais
MODELS_DIR = "data/models_s"
SCALER_PARAMS_FILE = "scaler_params.pkl"

class IPClassificationPredictor:
    """
    Classe para predição de classificação de IP capaz de rodar múltiplos modelos.
    """

    def __init__(
        self, models_dir=MODELS_DIR, scaler_params_file=SCALER_PARAMS_FILE
    ):
        self.models_dir = models_dir
        self.scaler_params_file = scaler_params_file
        self.model_name = None # Será definido dinamicamente
        self.model = None
        self.label_encoder = None
        self.scalers = None
        
        # Lista de modelos disponíveis
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
            "none": 1, "unknown": 2, "low": 3, 
            "medium": 4, "high": 5, "critical": 6,
        }

        self.expected_input_columns = [
            "ip", "abuseipdb_confidence_score", "abuseipdb_total_reports",
            "abuseipdb_num_distinct_users", 'apivoid_risk_score',
            'apivoid_blacklists_detection_rate', "risk_recommended_pulsedive",
            "virustotal_reputation", "virustotal_harmless", "virustotal_malicious",
            "virustotal_undetected", "virustotal_suspicious",
        ]

        self.model_feature_columns = [col for col in self.expected_input_columns if col != "ip"]

        self.logger = self._setup_logger()
        self._load_scaler_params()
        
        # Carrega o Label Encoder (comum a todos os modelos)
        self._load_label_encoder()

    def _setup_logger(self):
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger = logging.getLogger(f"ip_predictor_{timestamp}")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            file_handler = logging.FileHandler(os.path.join(logs_dir, f"ip_prediction_{timestamp}.log"))
            console_handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
        return logger

    def _load_scaler_params(self):
        if os.path.exists(self.scaler_params_file):
            try:
                with open(self.scaler_params_file, "rb") as f:
                    data = pickle.load(f)
                self.scalers = data["scalers"]
                self.scaler_columns = data["columns"]
                self.logger.info("Parâmetros do Scaler carregados.")
            except Exception as e:
                self.logger.error(f"Erro ao carregar scaler: {e}")
                self.scalers = None
        else:
            self.logger.error("Arquivo scaler_params.pkl não encontrado.")

    def _load_label_encoder(self):
        """Carrega apenas o Label Encoder"""
        path = os.path.join(self.models_dir, "label_encoder.joblib")
        if os.path.exists(path):
            self.label_encoder = joblib.load(path)
            self.logger.info(f"Label encoder carregado. Classes: {list(self.label_encoder.classes_)}")
        else:
            self.logger.error(f"Label encoder não encontrado em {path}")

    def switch_model(self, model_name):
        """Método auxiliar para trocar o modelo carregado na memória"""
        if model_name not in self.available_models:
            self.logger.error(f"Modelo {model_name} não disponível.")
            return False
        
        self.model_name = model_name
        filename = self.available_models[model_name]
        path = os.path.join(self.models_dir, filename)

        try:
            if not os.path.exists(path):
                self.logger.error(f"Arquivo do modelo não encontrado: {path}")
                return False

            if model_name == "CNN":
                import tensorflow as tf
                self.model = tf.keras.models.load_model(path)
            else:
                self.model = joblib.load(path)
            
            # self.logger.info(f"Modelo alterado para: {model_name}")
            return True
        except Exception as e:
            self.logger.error(f"Erro ao carregar modelo {model_name}: {e}")
            return False

    # ... (Mantenha os métodos _dict_to_dataframe, _validate_and_prepare_data, 
    # _handle_missing_values, _encode_categorical_columns e _normalize_features IGUAIS ao original) ...
    
    def _dict_to_dataframe(self, data_dict):
        if isinstance(data_dict, dict) and any(key in data_dict for key in ["ip", "abuseipdb_confidence_score"]):
            return pd.DataFrame([data_dict])
        elif isinstance(data_dict, list):
            return pd.DataFrame(data_dict)
        elif isinstance(data_dict, dict):
            return pd.DataFrame(data_dict)
        else:
            raise ValueError("Formato não suportado")

    def _validate_and_prepare_data(self, df):
        missing = set(self.expected_input_columns) - set(df.columns)
        if missing:
            raise ValueError(f"Colunas ausentes: {missing}")
        return df[self.expected_input_columns].copy()

    def _encode_categorical_columns(self, df):
        if "risk_recommended_pulsedive" in df.columns:
            df["risk_recommended_pulsedive"] = df["risk_recommended_pulsedive"].astype(str).map(self.risk_mapping).fillna(4)
        return df

    def _normalize_features(self, df):
        if self.scalers is None: return df
        for col in self.model_feature_columns:
            if col in df.columns and col in self.scalers:
                scaler = self.scalers[col]["scaler"]
                df[col] = scaler.transform(df[col].astype(float).values.reshape(-1, 1)).flatten()
        return df

    def preprocess_for_prediction(self, input_data):
        # Lógica simplificada chamando os métodos internos
        if isinstance(input_data, str):
            df = pd.read_csv(input_data)
        elif isinstance(input_data, (dict, list, pd.DataFrame)):
             # Reutiliza lógica de conversão se necessário, ou assume DF
             if isinstance(input_data, pd.DataFrame): df = input_data.copy()
             else: df = self._dict_to_dataframe(input_data)
        
        df = self._validate_and_prepare_data(df)
        df = self._encode_categorical_columns(df)
        df = self._normalize_features(df)
        return df

    def predict_all_models(self, input_data, output_file=None):
        """
        Executa a predição usando TODOS os modelos disponíveis.
        """
        self.logger.info("=== Iniciando Benchmark com TODOS os modelos ===")
        
        # 1. Pré-processamento (feito apenas uma vez)
        try:
            processed_df = self.preprocess_for_prediction(input_data)
            features_df = processed_df[self.model_feature_columns]
            features_np = features_df.values
        except Exception as e:
            self.logger.error(f"Erro no pré-processamento: {e}")
            return None

        # DataFrame final que conterá os resultados consolidados
        results_df = processed_df.copy()
        
        # Adiciona timestamp
        results_df["prediction_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 2. Loop pelos modelos
        for name in self.available_models.keys():
            self.logger.info(f"Processando modelo: {name}...")
            
            # Carrega o modelo atual
            success = self.switch_model(name)
            if not success:
                continue

            try:
                # Predição
                if name == "CNN":
                    # Reshape específico para CNN
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
                        confidences = [0.0] * len(predictions)

                # Decodifica classes
                predicted_labels = self.label_encoder.inverse_transform(predictions)

                # 3. Salva no DataFrame consolidado
                # Cria colunas específicas para cada modelo (ex: 'SVM_class', 'SVM_prob')
                results_df[f"{name}_class"] = predicted_labels
                results_df[f"{name}_prob"] = [round(c, 4) if c else 0.0 for c in confidences]

            except Exception as e:
                self.logger.error(f"Erro ao predizer com {name}: {e}")
                results_df[f"{name}_class"] = "ERROR"
                results_df[f"{name}_prob"] = 0.0

        # 4. Salva o resultado final
        if output_file:
            results_df.to_csv(output_file, index=False)
            self.logger.info(f"Relatório consolidado salvo em: {output_file}")
            
            # Pequeno resumo no log
            self.logger.info("Resumo das colunas geradas:")
            print(results_df.columns.tolist())

        return results_df

# --- EXECUÇÃO ---
if __name__ == "__main__":
    
    # Arquivos
    csv_file_path = "consulta.csv"
    
    # O arquivo de saída terá colunas para cada modelo
    output_csv_path = "datasets/prediction_results_all_models.csv"

    # Inicializa (sem passar model_name, pois usaremos todos)
    predictor = IPClassificationPredictor(MODELS_DIR, SCALER_PARAMS_FILE)

    # Executa para todos os modelos
    if os.path.exists(csv_file_path):
        final_results = predictor.predict_all_models(csv_file_path, output_csv_path)
        print("\nProcesso finalizado. Verifique a pasta 'datasets'.")
    else:
        print(f"Arquivo {csv_file_path} não encontrado.")