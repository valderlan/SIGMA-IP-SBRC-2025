# IP Classification

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Creation Date](https://img.shields.io/badge/Developed%20in%20July%202025-green)
![Last Update](https://img.shields.io/badge/Last%20update-July%202025-purple)

A complete IP address classification system using Machine Learning to detect malicious, suspicious, and benign IPs.

## Table of Contents

- [Overview](#overview)
- [Hyperparameters](#hyperparameters)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Execution Pipeline](#execution-pipeline)
- [How to Make Predictions](#how-to-make-predictions)
- [Available Models](#available-models)
- [Data Structure](#data-structure)
- [Important Files](#important-files)
- [Logs](#logs)
- [Metrics and Evaluation](#metrics)


## Overview

This project implements an IP classification system that:

- **Trains ML models** with data from multiple sources (AbuseIPDB, VirusTotal, IPVoid, PulseDive)
- **Normalizes data** using MinMaxScaler to ensure consistency
- **Supports 7 algorithms** (Random Forest, SVM, Neural Network, etc.)
- **Makes real-time predictions** for new IPs
- **Compares models** with and without SMOTE for class balancing

### Classification Classes:
- **Allowlist**: IPs considered safe
- **Suspicious**: IPs with suspicious behavior  
- **Denylist**: Provably malicious IPs

##  Classification Methodology

### **Approach: Weighted Voting**

The system uses an innovative methodology that combines information from multiple threat intelligence sources through a **weighted voting system**:

#### ** Data Sources:**
1. **AbuseIPDB** - Community-based malicious IP database
2. **VirusTotal** - Antivirus engine aggregator  
3. **IPVoid** - Suspicious IP detection service
4. **PulseDive** - Threat intelligence platform

#### ** Voting System:**
Each source contributes with "votes" based on:

- **Source confidence**: Weight assigned based on historical reliability
- **Indicator severity**: Risk scores (confidence, detections, reputation)
- **Engine consensus**: Number of engines that agree
- **Threat type detected**: Malware, phishing, spam, etc.

#### ** Classification Pipeline:**

```
IP Input → Multi-source Collection → Weighted Voting → Final Classification
    ↓              ↓                      ↓                 ↓
IP Address → Numerical Features → Calculated Weight → benign/suspicious/malicious
```

**Voting Example:**
```python
# Weights per source (simplified example)
abuseipdb_vote = confidence_score * 0.3
virustotal_vote = (malicious_engines / total_engines) * 0.25  
ipvoid_vote = (detections / max_detections) * 0.25
pulsedive_vote = risk_level_normalized * 0.2

final_score = sum(all_votes)
classification = classify_by_threshold(final_score)
```

#### ** Approach Advantages:**
- **Reduces false positives**: Consensus among multiple sources
- **Improves coverage**: Each source detects different threat types
- **Adaptable**: Weights can be adjusted based on performance
- **Robust**: Resistant to single source failures

#### ** Ground Truth Process:**
1. **Initial collection**: Raw data from each source
2. **Weighted voting**: Application of defined weights  
3. **Threshold definition**: Limits for each class
4. **Manual validation**: Sample verification for adjustment
5. **Final classification**: Generation of dataset_ip_classified.csv

This methodology ensures that classification is more accurate and reliable than using a single source in isolation.

## Hyperparameters 

**Hiperparameters**: [summary_report_with_smote.md](summary_report_with_smote.md)

**Hiperparameters**: [summary_report_without_smote.md](summary_report_with_smote.md)

## Project Structure

```
ip-classification/
├── 📁 config/
│   └── config.py                 # Pipeline configurations
├── 📁 src/
│   ├── data_processing.py        # Data preprocessing
│   ├── train.py                  # Model training
│   ├── models.py                 # Model definitions
│   ├── evaluate.py               # Model evaluation
│   ├── visualization.py          # Chart generation
│   └── normalize.py              # Data normalization
├── 📁 datasets/
│   ├── dataset_ip.csv            # Original dataset with classifications
│   ├── dataset_ip_norm.csv       # Normalized dataset for training
│   └── new_ips.csv               # Template for new IPs
├── 📁 data/
│   ├── 📁 models/               # Trained models (without SMOTE)
│   ├── 📁 models_s/             # Trained models (with SMOTE)
│   └── 📁 experiments/          # Experiment results
├── 📁 logs/                     # Execution logs
├── 📄 scaler_params.pkl         # Normalization parameters
├── 📄 ml_pipeline.py            # Main training pipeline
├── 📄 data_prep_pipeline.py     # To prepare the dataset
├── 📄 ip_predictor.py           # Prediction script
└── 📄 README.md                 # This documentation
```

## Installation

This project uses **uv** as dependency manager.

### 1. Install uv (if you don't have it):
```bash
# Windows
curl -LsSf https://astral.sh/uv/install.ps1 | powershell

# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Clone and setup project:
```bash
git clone <repository-url>
cd ip-classification

# Install dependencies
uv sync

# Activate virtual environment
uv shell
```

### 3. Main dependencies:
- pandas, numpy, scikit-learn
- tensorflow (for CNN model)
- matplotlib, seaborn (visualizations)
- joblib (model persistence)

## Execution Pipeline

### **Recommended Execution Order:**

#### **Data Preparation**
```bash
# Run for the dataset to be used in training
python data_prep_pipeline.py
```

#### **Model Training**
```bash
# Run complete training pipeline
python ml_pipeline.py
```

**What happens:**
- Loads `dataset_ip_classified.csv`
- Applies normalization (creates `dataset_ip_norm.csv`)
- Trains all models (with and without SMOTE)
- Saves models to `data/models/` and `data/models_s/`
- Generates reports and visualizations
- Creates `scaler_params.pkl`

#### **Make Predictions**
```bash
# Use prediction script
python ip_predictor.py
```

## How to Make Predictions

### **Model Configuration**

Edit the `ip_predictor.py` file:

```python
# Choose model
MODEL_NAME = "Random Forest"  # Options: "Random Forest", "SVM", "Neural Network", 
                              #         "Extra Trees", "Decision Tree", "KNN", "CNN"

# Choose model type (with or without SMOTE)
MODELS_DIR = "data/models"    # Without SMOTE
# MODELS_DIR = "data/models_s" # With SMOTE
```

### **Option 1: Single IP (Dictionary)**

```python
# Uncomment and configure:
single_ip_data = {
    "ip_address": "192.168.1.100",
    "abuseipdb_confidence_score": 25,
    "abuseipdb_total_reports": 3,
    "abuseipdb_num_distinct_users": 2,
    "ipvoid_detection_count": 1,
    "risk_recommended_pulsedive": "medium",
    "virustotal_reputation": 0,
    "virustotal_harmless": 45,
    "virustotal_malicious": 1,
    "virustotal_undetected": 25,
    "virustotal_suspicious": 0,
}

# Execute:
results = predictor.predict_classification(single_ip_data)
```

### **Option 2: Multiple IPs (CSV)**

```python
# Uncomment and configure:
csv_file_path = "datasets/new_ips.csv"
output_csv_path = "datasets/prediction_results.csv"

# Execute:
results = predictor.predict_classification(csv_file_path, output_csv_path)
```

### **Output Format:**
```python
{
    '192.168.1.100': {
        'classification': 'allowlist',      # allowlist, suspicious, denylist
        'confidence': 0.847,             # 0.0 to 1.0
        'model_used': 'Random Forest'    # Model used
    }
}
```

## Available Models

| Model | File | Description |
|-------|------|-------------|
| **Random Forest** | `Random Forest_model.joblib` | Tree ensemble (recommended) |
| **SVM** | `SVM_model.joblib` | Support Vector Machine |
| **Neural Network** | `Neural Network_model.joblib` | Multi-layer Perceptron |
| **Extra Trees** | `Extra Trees_model.joblib` | Extremely Randomized Trees |
| **Decision Tree** | `Decision Tree_model.joblib` | Single decision tree |
| **KNN** | `KNN_model.joblib` | K-Nearest Neighbors with PCA |
| **CNN** | `CNN_model.keras` | Convolutional Neural Network |

### **Difference between SMOTE and Without SMOTE:**
- **`data/models/`**: Models with `class_weight="balanced"`
- **`data/models_s/`**: Models trained with SMOTE (Synthetic Minority Oversampling)

## Data Structure

### **Required Columns (same structure as dataset_ip.csv):**

| Column | Type | Range | Description |
|--------|------|-------|-------------|
| `ip_address` | string | - | IP address |
| `abuseipdb_confidence_score` | int | 0-100 | AbuseIPDB confidence score |
| `abuseipdb_total_reports` | int | 0-85000 | Total reports |
| `abuseipdb_num_distinct_users` | int | 0-2000 | Unique users who reported |
| `ipvoid_detection_count` | int | 0-93 | IPVoid detection count |
| `risk_recommended_pulsedive` | string | unknown, none, low, medium, high, critical | PulseDive risk level |
| `virustotal_reputation` | int | -127 to 565 | VirusTotal reputation |
| `virustotal_harmless` | int | 0-86 | Engines that classified as harmless |
| `virustotal_malicious` | int | 0-20 | Engines that detected malware |
| `virustotal_undetected` | int | 0-91 | Engines that didn't detect |
| `virustotal_suspicious` | int | 0-5 | Engines that marked as suspicious |

## Important Files

### **`scaler_params.pkl` - CRITICAL FILE**

**What it is:**
- Contains MinMaxScaler normalization parameters used in training
- Maps each feature to its specific scaler with defined min/max

**Why it's important:**
- **Consistency**: Ensures new data is normalized exactly like training data
- **Reproducibility**: Allows applying same transformation in production
- **Accuracy**: Without it, predictions will be incorrect as models expect normalized data


** IMPORTANT:** 
- Never delete this file after training
- Generated automatically by `ml_pipeline.py`
- Required for any future prediction

### **Other important files:**

- **`label_encoder.joblib`**: Converts numeric classes back to text
- **`dataset_ip_norm.csv`**: Normalized dataset used in training
- **`*.joblib` / `*.keras`**: Trained models

## Logs

All scripts generate detailed logs in `logs/`:

```
logs/
├── pipeline_20241215_143022.log     # Training logs
├── training_20241215_143025.log     # Specific training logs
└── ip_prediction_20241215_150130.log # Prediction logs
```

**Information in logs:**
- Data and model loading
- Normalization process
- Evaluation metrics
- Errors and warnings
- Execution time

### **Debug Logs:**
- Always check logs in `logs/` for diagnosis
- Logs show exactly where error occurred
- Include information about normalization and model loading

## Metrics and Evaluation

Models are evaluated using:
- **Accuracy**: Overall precision
- **F1-Score**: Harmonic mean between precision and recall
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **Confidence**: Prediction probability (when available)

