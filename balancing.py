import pandas as pd
from imblearn.over_sampling import SMOTE

file_path = "datasets/dataset_cal_w.csv"
dataset = pd.read_csv(file_path)


X = dataset.drop(columns=["classificacao", "ip"])
y = dataset["classificacao"]


smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)


balanced_dataset = pd.concat(
    [pd.DataFrame(X_resampled), pd.DataFrame(y_resampled, columns=["classificacao"])],
    axis=1,
)


original_ips = dataset[["ip", "classificacao"]]


balanced_dataset["ip"] = balanced_dataset.index.map(
    lambda idx: (
        original_ips["ip"][idx] if idx < len(original_ips) else f"synthetic_ip_{idx}"
    )
)


balanced_dataset = balanced_dataset[
    ["ip"] + [col for col in balanced_dataset.columns if col != "ip"]
]


balanced_file_path = "datasets/balanced_resultado_cal_w.csv"
balanced_dataset.to_csv(balanced_file_path, index=False)

print(f"Dataset balanceado ajustado salvo como: {balanced_file_path}")
