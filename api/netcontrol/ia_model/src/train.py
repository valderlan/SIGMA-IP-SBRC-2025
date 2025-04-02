import os
import time

import joblib
import numpy as np
from sklearn.model_selection import GridSearchCV
from scikeras.wrappers import KerasClassifier
from sklearn.preprocessing import LabelEncoder

from config.config import PARAM_GRID

from .models import create_cnn_model, get_models
from .visualization import plot_learning_curves, plot_learning_curves_cnn

def train_and_evaluate_models_with_balancing(X_train, X_test, y_train, y_test, models_dir, images_dir):
    """
    Treina e avalia os modelos com tratamento para dados desbalanceados.
    
    Args:
        X_train (pd.DataFrame): Features de treino
        X_test (pd.DataFrame): Features de teste
        y_train (pd.Series): Labels de treino
        y_test (pd.Series): Labels de teste
        models_dir (str): Diretório para salvar os modelos
        images_dir (str): Diretório para salvar as imagens
        
    Returns:
        tuple: (resultados, tempos de execução, modelos treinados)
    """
    print("Treinando e avaliando modelos com ajuste para dados desbalanceados...")

    input_shape = (X_train.shape[1], 1)
    models = get_models(input_shape)
    results = {}
    execution_times = {}
    trained_models = {}

    for name, model in models.items():
        print(f"\nTreinando {name}...")
        start_time = time.time()

        if name == "CNN":
            model, hyperparameters = model  # Desempacota o modelo e hiperparâmetros
            X_train_reshaped = X_train.values.reshape(X_train.shape[0], X_train.shape[1], 1)
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)

            history = model.fit(
                X_train_reshaped,
                y_train,
                epochs=hyperparameters['epochs'],
                batch_size=hyperparameters['batch_size'],
                validation_split=0.2,
                verbose=0
            )
            
            # Avalia o modelo
            train_score = model.evaluate(X_train_reshaped, y_train, verbose=0)[1]
            test_score = model.evaluate(X_test_reshaped, y_test, verbose=0)[1]
            
            results[name] = {
                "Melhores Parâmetros": hyperparameters,
                "Score Treino": train_score,
                "Score Teste": test_score
            }
            trained_models[name] = model

            print(f"Gerando curvas de aprendizado para {name}...")
            plot_learning_curves_cnn(history, name, images_dir)

            model.save(os.path.join(models_dir, f"CNN_model.keras"))
        else:
            grid_search = GridSearchCV(
                model, 
                PARAM_GRID[name], 
                cv=5, 
                scoring="f1_weighted", 
                n_jobs=-1
            )
            
            try:
                grid_search.fit(X_train, y_train)
            except Exception as e:
                print(f"Erro ao treinar {name}: {str(e)}")
                continue

            results[name] = {
                "Melhores Parâmetros": grid_search.best_params_,
                "Score Treino": grid_search.score(X_train, y_train),
                "Score Teste": grid_search.score(X_test, y_test),
            }
            trained_models[name] = grid_search.best_estimator_

            print(f"Gerando curvas de aprendizado para {name}...")
            plot_learning_curves(
                grid_search.best_estimator_, 
                X_train, 
                y_train, 
                name, 
                images_dir
            )

            # Salva o modelo
            joblib.dump(
                grid_search.best_estimator_,
                os.path.join(models_dir, f"{name}_model.joblib")
            )

        execution_time = time.time() - start_time
        execution_times[name] = execution_time
        
        print(f"Resultados para {name}:")
        print(f"- Score Treino: {results[name]['Score Treino']:.4f}")
        print(f"- Score Teste: {results[name]['Score Teste']:.4f}")
        print(f"- Tempo de execução: {execution_time:.2f} segundos")
        
        if name != "CNN":
            print(f"- Melhores parâmetros: {results[name]['Melhores Parâmetros']}")

    # Salva o label encoder
    if os.path.exists(os.path.join(models_dir, "label_encoder.joblib")):
        print("\nLabel encoder já existe no diretório de modelos.")
    else:
        print("\nSalvando label encoder...")
        le = LabelEncoder()
        le.fit(y_train)
        joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))

    return results, execution_times, trained_models


