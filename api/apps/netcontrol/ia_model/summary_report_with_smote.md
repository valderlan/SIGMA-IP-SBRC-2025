# Model Execution Report

**Configuration**: WITH SMOTE


## Model Performance Summary

### Top 3 Models by Accuracy

1. **Random Forest**: 99.64%

2. **CNN**: 99.28%

3. **Extra Trees**: 97.67%


## Optimized Hyperparameters by Model

### Random Forest

```
{'max_depth': 7, 'max_features': 'sqrt', 'min_samples_leaf': 20, 'min_samples_split': 2, 'n_estimators': 200}
```

### SVM

```
{'C': 0.1, 'gamma': 'scale', 'kernel': 'rbf'}
```

### Neural Network

```
{'alpha': 0.01, 'hidden_layer_sizes': (30, 15), 'learning_rate': 'adaptive'}
```

### Extra Trees

```
{'max_depth': 7, 'min_samples_leaf': 20, 'min_samples_split': 2, 'n_estimators': 100}
```

### Decision Tree

```
{'max_depth': 6, 'max_features': 'sqrt', 'min_samples_leaf': 20, 'min_samples_split': 2}
```

### KNN

```
{'knn__leaf_size': 50, 'knn__metric': 'euclidean', 'knn__n_neighbors': 31, 'knn__p': 2, 'knn__weights': 'uniform', 'pca__n_components': 0.75}
```

### CNN

```
{'conv1_filters': 32, 'conv2_filters': 64, 'kernel_size': 3, 'dense1_units': 32, 'dense2_units': 16, 'dropout_rate': 0.5, 'learning_rate': 0.001, 'batch_size': 32, 'epochs': 10}
```


## Performance Metrics

|                |   Accuracy |   F1-Score |   Precision |   Recall |   Harmonic_Mean |
|:---------------|-----------:|-----------:|------------:|---------:|----------------:|
| Random Forest  |   0.996422 |   0.996424 |    0.996448 | 0.996422 |        0.996435 |
| SVM            |   0.912343 |   0.912233 |    0.914102 | 0.912343 |        0.913222 |
| Neural Network |   0.962433 |   0.963117 |    0.964405 | 0.962433 |        0.963418 |
| Extra Trees    |   0.976744 |   0.976552 |    0.977184 | 0.976744 |        0.976964 |
| Decision Tree  |   0.949911 |   0.951516 |    0.955624 | 0.949911 |        0.952759 |
| KNN            |   0.887299 |   0.893027 |    0.902677 | 0.887299 |        0.894922 |
| CNN            |   0.992844 |   0.992926 |    0.993236 | 0.992844 |        0.99304  |

## Detailed Accuracy Results

|                |   Correct |   Errors |   Accuracy (%) |
|:---------------|----------:|---------:|---------------:|
| Random Forest  |       557 |        2 |        99.6422 |
| SVM            |       510 |       49 |        91.2343 |
| Neural Network |       538 |       21 |        96.2433 |
| Extra Trees    |       546 |       13 |        97.6744 |
| Decision Tree  |       531 |       28 |        94.9911 |
| KNN            |       496 |       63 |        88.7299 |
| CNN            |       555 |        4 |        99.2844 |

## Training Execution Times

|                |   Time (seconds) |
|:---------------|-----------------:|
| Random Forest  |        13.7174   |
| SVM            |         9.67017  |
| CNN            |         3.94674  |
| Extra Trees    |         3.64945  |
| Neural Network |         2.89943  |
| KNN            |         0.446867 |
| Decision Tree  |         0.375396 |

**Total Training Time**: 34.71 seconds


