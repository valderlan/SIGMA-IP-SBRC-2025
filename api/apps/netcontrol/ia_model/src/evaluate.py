import pandas as pd
import numpy as np
import joblib
import os
from tensorflow.keras.models import load_model
from config.config import SCORE_COLS
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support

def evaluate_models(trained_models, X_test, y_test):
    
    metrics_dict = {
        'Acurácia': [],
        'F1-Score': [],
        'Precisão': [],
        'Recall': [],
        'Média Harmônica': []
    }
    
    model_names = []
    
    for name, model in trained_models.items():
        if name == 'CNN':
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred, axis=1)
        else:
            y_pred = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')
        precision, recall, _, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        harmonic_mean = 2 * (precision * recall) / (precision + recall)
        
        metrics_dict['Acurácia'].append(accuracy)
        metrics_dict['F1-Score'].append(f1)
        metrics_dict['Precisão'].append(precision)
        metrics_dict['Recall'].append(recall)
        metrics_dict['Média Harmônica'].append(harmonic_mean)
        model_names.append(name)
    
    metrics_df = pd.DataFrame(metrics_dict, index=model_names)
    return metrics_df

def evaluate_model_accuracy(trained_models, X_test, y_test, le):
    """
    Avalia a acurácia dos modelos no conjunto de teste.
    
    Args:
        trained_models: Dicionário com os modelos treinados
        X_test: Features do conjunto de teste
        y_test: Labels verdadeiros do conjunto de teste
        le: LabelEncoder usado para transformar as classes
    
    Returns:
        pd.DataFrame: DataFrame com as métricas de acurácia para cada modelo
    """
    accuracy_results = {}
    
    for name, model in trained_models.items():
        if name == 'CNN':
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)
            y_pred = model.predict(X_test_reshaped)
            y_pred = np.argmax(y_pred, axis=1)
        else:
            y_pred = model.predict(X_test)
        
        
        y_pred_labels = le.inverse_transform(y_pred)
        y_test_labels = le.inverse_transform(y_test)
        
        correct_predictions = sum(y_pred_labels == y_test_labels)
        total_predictions = len(y_test_labels)
        accuracy = (correct_predictions / total_predictions) * 100
        
        accuracy_results[name] = {
            'Acertos': correct_predictions,
            'Erros': total_predictions - correct_predictions,
            'Acurácia (%)': accuracy
        }
    
    return pd.DataFrame(accuracy_results).T

def save_evaluation_results(metrics_df, accuracy_df, output_dir):
    
    metrics_df.to_csv(os.path.join(output_dir, 'metrics_results.csv'))
    accuracy_df.to_csv(os.path.join(output_dir, 'accuracy_results.csv'))
    print("Resultados salvos com sucesso!")