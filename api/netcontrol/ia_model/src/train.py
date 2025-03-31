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

    models = get_models()
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


'''def train_and_evaluate_models_with_balancing(
    X_train, X_test, y_train, y_test, models_dir, images_dir
):

    print("Treinando e avaliando modelos com ajuste para dados desbalanceados...")

    models = get_models()
    models["CNN"] = create_cnn_model((X_train.shape[1], 1))

    results = {}
    execution_times = {}
    trained_models = {}

    for name, model in models.items():
        print(f"\nTreinando {name}...")
        start_time = time.time()

        if name == "CNN":
            X_train_reshaped = X_train.values.reshape(
                X_train.shape[0], X_train.shape[1], 1
            )
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)

            history = model.fit(
                X_train_reshaped,
                y_train,
                epochs=10,
                batch_size=32,
                validation_split=0.2,
                verbose=0,
            )
            test_score = model.evaluate(X_test_reshaped, y_test, verbose=0)[1]
            results[name] = {"Score Teste": test_score}
            trained_models[name] = model

            print(f"Gerando curvas de aprendizado para {name}...")
            plot_learning_curves_cnn(history, name, images_dir)

            model.save(os.path.join(models_dir, f"CNN_model.keras"))
        else:
            grid_search = GridSearchCV(
                model, PARAM_GRID[name], cv=5, scoring="f1_weighted", n_jobs=-1
            )
            grid_search.fit(X_train, y_train)
            print(f"Hiperparâmetros ótimos para {name}: {grid_search.best_params_}")

            results[name] = {
                "Melhores Parâmetros": grid_search.best_params_,
                "Score Treino": grid_search.score(X_train, y_train),
                "Score Teste": grid_search.score(X_test, y_test),
            }
            trained_models[name] = grid_search.best_estimator_

            print(f"Gerando curvas de aprendizado para {name}...")
            plot_learning_curves(
                grid_search.best_estimator_, X_train, y_train, name, images_dir
            )

            joblib.dump(
                grid_search.best_estimator_,
                os.path.join(models_dir, f"{name}_model.joblib"),
            )

        execution_time = time.time() - start_time
        execution_times[name] = execution_time
        print(f"Tempo de execução para {name}: {execution_time:.2f} segundos")

    return results, execution_times, trained_models'''


'''def train_and_evaluate_models_with_balancing(
    X_train, X_test, y_train, y_test, models_dir, images_dir
):
    #import time

    #import joblib
    #from sklearn.model_selection import GridSearchCV

    print("Treinando e avaliando modelos com ajuste para dados desbalanceados...")

    models = get_models()
    # Remova ou não insira a CNN na lista original, pois vamos tratar a CNN separadamente com grid search
    # models["CNN"] = create_cnn_model((X_train.shape[1], 1))

    results = {}
    execution_times = {}
    trained_models = {}

    # Primeiro, trate os modelos não CNN com GridSearchCV como já vem fazendo:
    for name, model in models.items():
        print(f"\nTreinando {name}...")
        start_time = time.time()

        if name != "CNN":
            grid_search = GridSearchCV(
                model, PARAM_GRID[name], cv=5, scoring="f1_weighted", n_jobs=-1
            )
            grid_search.fit(X_train, y_train)

            results[name] = {
                "Melhores Parâmetros": grid_search.best_params_,
                "Score Treino": grid_search.score(X_train, y_train),
                "Score Teste": grid_search.score(X_test, y_test),
            }
            trained_models[name] = grid_search.best_estimator_

            print(f"Gerando curvas de aprendizado para {name}...")
            plot_learning_curves(
                grid_search.best_estimator_, X_train, y_train, name, images_dir
            )

            joblib.dump(
                grid_search.best_estimator_,
                os.path.join(models_dir, f"{name}_model.joblib"),
            )
        else:
            # Se desejar incluir a CNN na busca em grade, use o KerasClassifier:
            # Primeiro, defina o input_shape para a função de criação da CNN:
            input_shape = X_train.shape[1]  # Número de features
            # Redimensiona os dados para (n_amostras, n_features, 1)
            X_train_reshaped = X_train.values.reshape(
                X_train.shape[0], X_train.shape[1], 1
            )
            X_test_reshaped = X_test.values.reshape(X_test.shape[0], X_test.shape[1], 1)

            # Cria o wrapper da CNN
            cnn_wrapper = KerasClassifier(
                model=create_cnn_model_wrapper,
                epochs=10,
                batch_size=32,
                verbose=0,
                # Passe o input_shape como argumento adicional:
                model__input_shape=input_shape,
            )

            # Defina um grid de hiperparâmetros para a CNN (por exemplo, taxa de aprendizado e batch_size)
            cnn_param_grid = {
                "model__learning_rate": [0.001, 0.0001],
                "batch_size": [32, 64],
            }

            grid_search = GridSearchCV(
                cnn_wrapper,
                cnn_param_grid,
                cv=5,
                scoring="f1_weighted",
                n_jobs=-1,
            )

            grid_search.fit(X_train_reshaped, y_train)

            test_score = grid_search.score(X_test_reshaped, y_test)
            results["CNN"] = {
                "Melhores Parâmetros": grid_search.best_params_,
                "Score Teste": test_score,
            }
            trained_models["CNN"] = grid_search.best_estimator_

            print(f"Gerando curvas de aprendizado para CNN...")
            # Se desejar, você pode gerar as curvas de aprendizado usando o histórico retornado pelo fit
            # (note que, ao usar o GridSearchCV, o acesso ao histórico pode não ser tão direto)

            # Salva o modelo treinado (como arquivo Keras, por exemplo)
            grid_search.best_estimator_.model.save(
                os.path.join(models_dir, "CNN_model.keras")
            )

        execution_time = time.time() - start_time
        execution_times[name] = execution_time
        print(f"Tempo de execução para {name}: {execution_time:.2f} segundos")

    return results, execution_times, trained_models'''
