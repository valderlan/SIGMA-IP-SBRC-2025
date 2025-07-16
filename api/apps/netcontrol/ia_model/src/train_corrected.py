import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GridSearchCV
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

from config.config import PARAM_GRID

# Importar models corrigido ou usar versão inline se não existir
try:
    from .models_corrected import get_models
except ImportError:
    # Fallback: usar models original com adaptações
    from .models import get_models
    print("⚠️  Usando models.py original. Recomendado criar models_corrected.py")

from .visualization import plot_learning_curves, plot_learning_curves_cnn


def train_and_evaluate_models_corrected(X_train, X_test, y_train, y_test, models_dir, images_dir, use_smote=False):
    """
    Treina e avalia os modelos COM CORREÇÃO DO DATA LEAKAGE.
    
    Args:
        X_train (pd.DataFrame): Features de treino
        X_test (pd.DataFrame): Features de teste  
        y_train (pd.Series): Labels de treino
        y_test (pd.Series): Labels de teste
        models_dir (str): Diretório para salvar os modelos
        images_dir (str): Diretório para salvar as imagens
        use_smote (bool): Se deve aplicar SMOTE no conjunto de treino
        
    Returns:
        tuple: (resultados, tempos de execução, modelos treinados)
    """
    
    smote_status = "COM SMOTE (aplicado corretamente)" if use_smote else "SEM SMOTE"
    print(f"Treinando e avaliando modelos - {smote_status}...")
    
    # 1. Aplicar SMOTE apenas no conjunto de treino (se solicitado)
    if use_smote:
        print("🔧 Aplicando SMOTE APENAS no conjunto de treino...")
        
        # Verificar distribuição original
        print("   Distribuição original do treino:")
        if hasattr(y_train, 'value_counts'):
            print(y_train.value_counts().to_string())
        else:
            print(pd.Series(y_train).value_counts().to_string())
        
        # Aplicar SMOTE
        smote = SMOTE(random_state=42)
        X_train_processed, y_train_processed = smote.fit_resample(X_train, y_train)
        
        print("   Distribuição após SMOTE:")
        print(pd.Series(y_train_processed).value_counts().to_string())
        print(f"   Treino aumentou de {X_train.shape[0]} para {X_train_processed.shape[0]} amostras")
        
    else:
        print("🔧 Mantendo conjunto de treino original (sem SMOTE)...")
        X_train_processed = X_train.copy()
        y_train_processed = y_train.copy()
        
        print("   Distribuição do treino:")
        if hasattr(y_train_processed, 'value_counts'):
            print(y_train_processed.value_counts().to_string())
        else:
            print(pd.Series(y_train_processed).value_counts().to_string())
    
    # 2. Configurar modelos baseado na estratégia escolhida
    input_shape = (X_train_processed.shape[1], 1)
    
    # Tentar usar get_models corrigido, senão usar adaptação
    try:
        models = get_models(input_shape, use_smote=use_smote)
    except TypeError:
        # Fallback para models.py original
        print("⚠️  Usando configuração de modelos adaptada...")
        models = get_models_adapted(input_shape, use_smote)
    
    results = {}
    execution_times = {}
    trained_models = {}

    # 3. Treinar cada modelo
    for name, model in models.items():
        print(f"\nTreinando {name}...")
        start_time = time.time()

        if name == "CNN":
            model, hyperparameters = model  # Desempacota o modelo e hiperparâmetros
            
            # Preparar dados para CNN
            X_train_reshaped = X_train_processed.values.reshape(
                X_train_processed.shape[0], X_train_processed.shape[1], 1
            )
            X_test_reshaped = X_test.values.reshape(
                X_test.shape[0], X_test.shape[1], 1
            )

            # Treinar CNN
            history = model.fit(
                X_train_reshaped,
                y_train_processed,
                epochs=hyperparameters['epochs'],
                batch_size=hyperparameters['batch_size'],
                validation_split=0.2,
                verbose=0
            )
            
            # Avaliar o modelo
            train_score = model.evaluate(X_train_reshaped, y_train_processed, verbose=0)[1]
            test_score = model.evaluate(X_test_reshaped, y_test, verbose=0)[1]
            
            results[name] = {
                "Melhores Parâmetros": hyperparameters,
                "Score Treino": train_score,
                "Score Teste": test_score
            }
            trained_models[name] = model

            # Gerar curvas de aprendizado
            print(f"Gerando curvas de aprendizado para {name}...")
            plot_learning_curves_cnn(history, name, images_dir)

            # Salvar modelo
            model.save(os.path.join(models_dir, f"CNN_model.keras"))
            
        else:
            # Treinar modelos sklearn
            grid_search = GridSearchCV(
                model, 
                PARAM_GRID[name], 
                cv=5, 
                scoring="f1_weighted", 
                n_jobs=-1
            )
            
            try:
                grid_search.fit(X_train_processed, y_train_processed)
            except Exception as e:
                print(f"Erro ao treinar {name}: {str(e)}")
                continue

            # Avaliar nos conjuntos de treino e teste
            train_score = grid_search.score(X_train_processed, y_train_processed)
            test_score = grid_search.score(X_test, y_test)
            
            results[name] = {
                "Melhores Parâmetros": grid_search.best_params_,
                "Score Treino": train_score,
                "Score Teste": test_score,
            }
            trained_models[name] = grid_search.best_estimator_

            # Gerar curvas de aprendizado
            print(f"Gerando curvas de aprendizado para {name}...")
            plot_learning_curves(
                grid_search.best_estimator_, 
                X_train_processed, 
                y_train_processed, 
                name, 
                images_dir
            )

            # Salvar modelo
            joblib.dump(
                grid_search.best_estimator_,
                os.path.join(models_dir, f"{name}_model.joblib")
            )

        # Calcular tempo de execução
        execution_time = time.time() - start_time
        execution_times[name] = execution_time
        
        # Log dos resultados
        print(f"Resultados para {name}:")
        print(f"- Score Treino: {results[name]['Score Treino']:.4f}")
        print(f"- Score Teste: {results[name]['Score Teste']:.4f}")
        print(f"- Tempo de execução: {execution_time:.2f} segundos")
        
        if name != "CNN":
            print(f"- Melhores parâmetros: {results[name]['Melhores Parâmetros']}")

    # 4. Salvar label encoder
    if os.path.exists(os.path.join(models_dir, "label_encoder.joblib")):
        print("\nLabel encoder já existe no diretório de modelos.")
    else:
        print("\nSalvando label encoder...")
        le = LabelEncoder()
        le.fit(y_train_processed)  # Usar dados processados
        joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))

    # 5. Log final
    print(f"\n✅ Treinamento concluído - {smote_status}")
    print(f"📊 {len(trained_models)} modelos treinados com sucesso")
    print(f"💾 Modelos salvos em: {models_dir}")
    
    return results, execution_times, trained_models


def get_models_adapted(input_shape, use_smote):
    """
    Função adaptada para usar models.py original com configurações corretas.
    """
    from sklearn.decomposition import PCA
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import SVC
    from sklearn.tree import DecisionTreeClassifier
    from tensorflow.keras.layers import (
        BatchNormalization, Conv1D, Dense, Dropout, Flatten, Input, MaxPooling1D,
    )
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.optimizers import Adam
    
    # Criar modelo CNN
    def create_cnn_model_local(input_shape):
        hyperparameters = {
            'conv1_filters': 32, 'conv2_filters': 64, 'kernel_size': 3,
            'dense1_units': 32, 'dense2_units': 16, 'dropout_rate': 0.2,
            'learning_rate': 0.001, 'batch_size': 32, 'epochs': 10
        }
        
        model = Sequential([
            Input(shape=input_shape),
            Conv1D(hyperparameters['conv1_filters'], 
                   kernel_size=hyperparameters['kernel_size'], 
                   padding="same", activation="relu"),
            BatchNormalization(),
            Conv1D(hyperparameters['conv2_filters'], 
                   kernel_size=hyperparameters['kernel_size'], 
                   padding="same", activation="relu"),
            BatchNormalization(),
            Flatten(),
            Dense(hyperparameters['dense1_units'], activation="relu"),
            Dropout(hyperparameters['dropout_rate']),
            Dense(hyperparameters['dense2_units'], activation="relu"),
            Dense(3, activation="softmax"),
        ])

        model.compile(
            optimizer=Adam(learning_rate=hyperparameters['learning_rate']),
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )
        return model, hyperparameters
    
    cnn_model, cnn_params = create_cnn_model_local(input_shape)
    
    # Configurar class_weight baseado em use_smote
    class_weight = None if use_smote else "balanced"
    
    print(f"🔧 Configurando modelos - class_weight: {class_weight}")
    
    return {
        "Random Forest": RandomForestClassifier(
            class_weight=class_weight, random_state=42
        ),
        "SVM": SVC(
            class_weight=class_weight, probability=True, random_state=42
        ),
        "Neural Network": MLPClassifier(
            max_iter=1000, random_state=42, learning_rate_init=0.001,
            early_stopping=True, validation_fraction=0.1, n_iter_no_change=10,
            hidden_layer_sizes=(100, 50), activation="relu", solver="adam",
            batch_size="auto", shuffle=True, verbose=False,
        ),
        "Extra Trees": ExtraTreesClassifier(
            class_weight=class_weight, random_state=42
        ),
        "Decision Tree": DecisionTreeClassifier(
            class_weight=class_weight, random_state=42
        ),
        "KNN": Pipeline([
            ("scaler", StandardScaler()),
            ("pca", PCA()),
            ("knn", KNeighborsClassifier()),
        ]),
        "CNN": (cnn_model, cnn_params)
    }


def train_and_evaluate_models_with_balancing(X_train, X_test, y_train, y_test, models_dir, images_dir):
    """
    Função de compatibilidade com o código antigo.
    DEPRECATED: Use train_and_evaluate_models_corrected() com parâmetro use_smote.
    """
    print("⚠️  Usando função legacy. Migrando para versão corrigida...")
    return train_and_evaluate_models_corrected(
        X_train, X_test, y_train, y_test, models_dir, images_dir, use_smote=False
    )