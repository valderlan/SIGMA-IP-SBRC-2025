# ENIAC-2025

## Hiperparâmetros Otimizados por Modelo

| Modelo               | Hiperparâmetros |
|----------------------|----------------|
| **Random Forest**    | `max_depth`: 12, `max_features`: "sqrt", `min_samples_leaf`: 3, `min_samples_split`: 2, `n_estimators`: 100 |
| **SVM**             | `C`: 1, `gamma`: "scale", `kernel`: "rbf" |
| **Neural Network**  | `alpha`: 0.001, `hidden_layer_sizes`: (50, 25), `learning_rate`: "adaptive" |
| **Extra Trees**     | `max_depth`: 15, `min_samples_split`: 4, `n_estimators`: 200 |
| **Decision Tree**   | `max_depth`: 10, `max_features`: "sqrt", `min_samples_leaf`: 3, `min_samples_split`: 2 |
| **KNN**            | `leaf_size`: 50, `metric`: "euclidean", `n_neighbors`: 33, `p`: 2, `weights`: "uniform", `pca_n_components`: 0.65 |
| **CNN**            | `conv1_filters`: 32, `conv2_filters`: 64, `kernel_size`: 3, `dense1_units`: 32, `dense2_units`: 16, `dropout_rate`: 0.2, `learning_rate`: 0.001, `batch_size`: 32, `epochs`: 10 |