from sklearn.decomposition import PCA
from sklearn.ensemble import (
    AdaBoostClassifier,
    ExtraTreesClassifier,
    RandomForestClassifier,
    StackingClassifier,
    VotingClassifier,
)
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
from tensorflow.keras.regularizers import l1_l2


def create_cnn_model(input_shape):
    """
    Create a CNN model and return the model and its hyperparameters.
    """
    hyperparameters = {
        "conv1_filters": 32,
        "conv2_filters": 64,
        "kernel_size": 3,
        "dense1_units": 32,
        "dense2_units": 16,
        "dropout_rate": 0.5,
        "learning_rate": 0.001,
        "batch_size": 32,
        "epochs": 10,
    }

    model = Sequential(
        [
            Input(shape=input_shape),
            Conv1D(
                hyperparameters["conv1_filters"],
                kernel_size=hyperparameters["kernel_size"],
                padding="same",
                activation="relu",
                kernel_regularizer=l1_l2(l1=1e-5, l2=1e-4),
            ),
            BatchNormalization(),
            Conv1D(
                hyperparameters["conv2_filters"],
                kernel_size=hyperparameters["kernel_size"],
                padding="same",
                activation="relu",
            ),
            BatchNormalization(),
            Flatten(),
            Dense(
                hyperparameters["dense1_units"],
                activation="relu",
                kernel_regularizer=l1_l2(l1=1e-5, l2=1e-3),
            ),
            Dropout(hyperparameters["dropout_rate"]),
            Dense(hyperparameters["dense2_units"], activation="relu"),
            Dense(3, activation="softmax"),
        ]
    )

    model.compile(
        optimizer=Adam(learning_rate=hyperparameters["learning_rate"]),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )

    return model, hyperparameters


def get_base_estimators(use_smote=False):
    """Retorna um subconjunto de modelos como estimadores base para ensembles."""
    class_weight = None if use_smote else "balanced"

    estimators = [
        ("rf", RandomForestClassifier(random_state=42, class_weight=class_weight)),
        ("svc", SVC(probability=True, random_state=42, class_weight=class_weight)),
        (
            "knn",
            Pipeline(
                [
                    ("scaler", StandardScaler()),
                    ("pca", PCA(n_components=5)),
                    ("knn", KNeighborsClassifier()),
                ]
            ),
        ),
    ]
    return estimators


def get_models_with_smote(input_shape=None):
    """
    Return models configured for use WITH SMOTE.
    Removes class_weight="balanced" to avoid double balancing.

    Args:
        input_shape: Tuple (features, 1) for CNN model

    Returns:
        dict: Dictionary with model instances
    """
    if input_shape is None:
        input_shape = (11, 1)

    cnn_model, cnn_params = create_cnn_model(input_shape)

    estimators = get_base_estimators(use_smote=True)
    voting_clf = VotingClassifier(estimators=estimators, voting="soft", n_jobs=-1)
    stacking_clf = StackingClassifier(
        estimators=estimators,
        final_estimator=RandomForestClassifier(random_state=42),
        cv=5,
        n_jobs=-1,
    )

    return {
        "Random Forest": RandomForestClassifier(random_state=42),
        "SVM": SVC(probability=True, random_state=42),
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
        "Extra Trees": ExtraTreesClassifier(random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "KNN": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("pca", PCA()),
                ("knn", KNeighborsClassifier()),
            ]
        ),
        "CNN": (cnn_model, cnn_params),
        "AdaBoost": AdaBoostClassifier(random_state=42),
        "Voting": voting_clf,
        "Stacking": stacking_clf,
    }


def get_models_without_smote(input_shape=None):
    """
    Return models configured for use WITHOUT SMOTE.
    Maintains class_weight="balanced" to handle natural imbalance.

    Args:
        input_shape: Tuple (features, 1) for CNN model

    Returns:
        dict: Dictionary with model instances
    """
    if input_shape is None:
        input_shape = (11, 1)

    cnn_model, cnn_params = create_cnn_model(input_shape)

    estimators = get_base_estimators(use_smote=False)
    voting_clf = VotingClassifier(estimators=estimators, voting="soft", n_jobs=-1)
    stacking_clf = StackingClassifier(
        estimators=estimators,
        final_estimator=RandomForestClassifier(
            class_weight="balanced", random_state=42
        ),
        cv=5,
        n_jobs=-1,
    )

    return {
        "Random Forest": RandomForestClassifier(
            class_weight="balanced", random_state=42
        ),
        "SVM": SVC(
            class_weight="balanced",
            probability=True,
            random_state=42,
        ),
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
        "CNN": (cnn_model, cnn_params),
        "AdaBoost": AdaBoostClassifier(random_state=42),
        "Voting": voting_clf,
        "Stacking": stacking_clf,
    }


def get_models(input_shape=None, use_smote=False):
    """
    Unified function to get models based on configuration.

    Args:
        input_shape: Tuple (features, 1) for CNN model
        use_smote: Boolean indicating whether SMOTE will be used

    Returns:
        dict: Dictionary with appropriate model instances
    """
    if use_smote:
        return get_models_with_smote(input_shape)
    else:
        return get_models_without_smote(input_shape)


def get_models_legacy(input_shape=None):
    """
    Legacy function for compatibility.
    DEPRECATED: Use get_models() with use_smote parameter.
    """
    return get_models_without_smote(input_shape)
