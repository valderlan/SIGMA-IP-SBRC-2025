# Model Execution Report

**Configuration**: WITHOUT SMOTE


## Model Performance Summary

### Top 3 Models by Accuracy

1. **Random Forest**: 98.21%

2. **Extra Trees**: 96.60%

3. **Decision Tree**: 92.67%


## Optimized Hyperparameters by Model

### Random Forest

```
{'max_depth': 7, 'max_features': 'sqrt', 'min_samples_leaf': 20, 'min_samples_split': 2, 'n_estimators': 100}
```

### SVM

```
{'C': 0.1, 'gamma': 'scale', 'kernel': 'rbf'}
```

### Neural Network

```
{'alpha': 0.1, 'hidden_layer_sizes': (30,), 'learning_rate': 'adaptive'}
```

### Extra Trees

```
{'max_depth': 7, 'min_samples_leaf': 20, 'min_samples_split': 2, 'n_estimators': 200}
```

### Decision Tree

```
{'max_depth': 6, 'max_features': 'sqrt', 'min_samples_leaf': 25, 'min_samples_split': 2}
```

### KNN

```
{'knn__leaf_size': 50, 'knn__metric': 'euclidean', 'knn__n_neighbors': 31, 'knn__p': 2, 'knn__weights': 'uniform', 'pca__n_components': 0.65}
```

### CNN

```
{'conv1_filters': 32, 'conv2_filters': 64, 'kernel_size': 3, 'dense1_units': 32, 'dense2_units': 16, 'dropout_rate': 0.5, 'learning_rate': 0.001, 'batch_size': 32, 'epochs': 10}
```


## Performance Metrics

|                |   Accuracy |   F1-Score |   Precision |   Recall |   Harmonic_Mean |
|:---------------|-----------:|-----------:|------------:|---------:|----------------:|
| Random Forest  |   0.982111 |   0.982424 |    0.983371 | 0.982111 |        0.98274  |
| SVM            |   0.912343 |   0.901975 |    0.913527 | 0.912343 |        0.912935 |
| Neural Network |   0.878354 |   0.831024 |    0.867148 | 0.878354 |        0.872715 |
| Extra Trees    |   0.966011 |   0.964898 |    0.965876 | 0.966011 |        0.965944 |
| Decision Tree  |   0.926655 |   0.930738 |    0.951875 | 0.926655 |        0.939096 |
| KNN            |   0.905188 |   0.895909 |    0.897437 | 0.905188 |        0.901296 |
| CNN            |   0.919499 |   0.920508 |    0.945119 | 0.919499 |        0.932133 |

## Detailed Accuracy Results

|                |   Correct |   Errors |   Accuracy (%) |
|:---------------|----------:|---------:|---------------:|
| Random Forest  |       549 |       10 |        98.2111 |
| SVM            |       510 |       49 |        91.2343 |
| Neural Network |       491 |       68 |        87.8354 |
| Extra Trees    |       540 |       19 |        96.6011 |
| Decision Tree  |       518 |       41 |        92.6655 |
| KNN            |       506 |       53 |        90.5188 |
| CNN            |       514 |       45 |        91.9499 |

## Training Execution Times

|                |   Time (seconds) |
|:---------------|-----------------:|
| Random Forest  |         9.88994  |
| Extra Trees    |         3.13522  |
| CNN            |         3.04342  |
| SVM            |         2.17165  |
| Neural Network |         0.492251 |
| Decision Tree  |         0.381482 |
| KNN            |         0.315621 |

**Total Training Time**: 19.43 seconds


