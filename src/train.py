import os
import time

import joblib
import numpy as np
from sklearn.model_selection import GridSearchCV

from config.config import PARAM_GRID

from .models import create_cnn_model, get_models
from .visualization import plot_learning_curves, plot_learning_curves_cnn


def train_and_evaluate_models_with_balancing(
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

    return results, execution_times, trained_models
