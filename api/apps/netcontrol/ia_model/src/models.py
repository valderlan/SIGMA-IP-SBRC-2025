from sklearn.decomposition import PCA
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from tensorflow.keras.layers import (
    BatchNormalization,
    Conv1D,
    Dense,
    Dropout,
    Flatten,
    Input,
    MaxPooling1D,
)
from tensorflow.keras.models import Sequential
from tensorflow.keras.optimizers import Adam


def create_cnn_model(input_shape):
    """
    Cria um modelo CNN e retorna o modelo e seus hiperparâmetros.
    """
    hyperparameters = {
        'conv1_filters': 32,
        'conv2_filters': 64,
        'kernel_size': 3,
        'dense1_units': 32,
        'dense2_units': 16,
        'dropout_rate': 0.2,
        'learning_rate': 0.001,
        'batch_size': 32,
        'epochs': 10
    }
    
    model = Sequential([
        Input(shape=input_shape),
        Conv1D(hyperparameters['conv1_filters'], 
               kernel_size=hyperparameters['kernel_size'], 
               padding="same", 
               activation="relu"),
        BatchNormalization(),
        Conv1D(hyperparameters['conv2_filters'], 
               kernel_size=hyperparameters['kernel_size'], 
               padding="same", 
               activation="relu"),
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

def get_models(input_shape=None):
    """
    Creates and returns model instances for different algorithms.
    
    Args:
        input_shape: Optional tuple (features, 1) for CNN model 
                    (defaults to (11, 1) if not provided)
    
    Returns:
        dict: Dictionary of model instances
    """
    if input_shape is None:
        input_shape = (11, 1)  # Default, but should be overridden with actual data shape
        
    cnn_model, cnn_params = create_cnn_model(input_shape)

    return {
        "Random Forest": RandomForestClassifier(
            class_weight="balanced", random_state=42
        ),
        "SVM": SVC(class_weight="balanced", probability=True, random_state=42),
        "Neural Network": MLPClassifier(
            max_iter=1000,
            random_state=42,
            learning_rate_init=0.001,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=10,
            hidden_layer_sizes=(100, 50),
            activation="relu",
            solver="adam",
            batch_size="auto",
            shuffle=True,
            verbose=False,
        ),
        "Extra Trees": ExtraTreesClassifier(class_weight="balanced", random_state=42),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", random_state=42
        ),
        "KNN": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("pca", PCA()),
                ("knn", KNeighborsClassifier()),
            ]
        ),
        "CNN": (cnn_model, cnn_params)
    }


'''def get_models():
    cnn_model, cnn_params = create_cnn_model((11, 1))

    return {
        "Random Forest": RandomForestClassifier(
            class_weight="balanced", random_state=42
        ),
        "SVM": SVC(class_weight="balanced", probability=True, random_state=42),
        "Neural Network": MLPClassifier(
            max_iter=1000,  # Aumentado para 1000 iterações
            random_state=42,
            learning_rate_init=0.001,
            early_stopping=True,  # Adiciona early stopping
            validation_fraction=0.1,  # 10% dos dados para validação
            n_iter_no_change=10,  # Número de iterações sem melhoria para parar
            hidden_layer_sizes=(100, 50),  # Duas camadas ocultas
            activation="relu",
            solver="adam",
            batch_size="auto",
            shuffle=True,
            verbose=False,
        ),
        "Extra Trees": ExtraTreesClassifier(class_weight="balanced", random_state=42),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", random_state=42
        ),
        "KNN": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("pca", PCA()),
                ("knn", KNeighborsClassifier()),
            ]
        ),
        "CNN": (cnn_model, cnn_params)
    }'''
