import sys

from feature_normalizer import FeatureNormalizer
from predict_new_data import get_available_models, predict_ip_classification

models_dir = "data/experiments/experiment_20250108_102855/models"


available_models = get_available_models(models_dir)
print(f"Modelos disponíveis: {available_models}")


selected_model = "Random Forest"

#dataset_path = "datasets/Total_test.csv"  # local e dataset que será normalizado
#output_path = "datasets/teste1.csv"  # local e dataset de saida normalizado

# Pega os argumentos da linha de comando
dataset_path = sys.argv[1]
output_path = sys.argv[2]


file_normalizer = FeatureNormalizer()
file_normalizer.aplicar_pesos_em_novo_dataset(dataset_path, output_path)

predictions = predict_ip_classification(
    input_path=output_path, 
    models_dir=models_dir, 
    model_name=selected_model
)


print("\nPrevisões usando", selected_model)
print(predictions)
print(predictions)
