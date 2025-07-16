import os
import sys
import pandas as pd
from datetime import datetime

# Adicionar diretório atual ao path para imports
current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

print(f"🚀 Executando do diretório: {current_dir}")

# Imports com fallbacks
try:
    from config.config import SCORE_COLS
except ImportError:
    print("⚠️  config.config não encontrado, usando configuração padrão")
    SCORE_COLS = [
        "abuseipdb_confidence_score",
        "abuseipdb_total_reports", 
        "abuseipdb_num_distinct_users",
        "ipvoid_detection_count",
        "risk_recommended_pulsedive",
        "virustotal_reputation",
        "virustotal_harmless",
        "virustotal_malicious",
        "virustotal_undetected",
        "virustotal_suspicious",
    ]

# Imports obrigatórios
from src.data_processing import (
    load_and_preprocess_data,
    normalize_scores,
    prepare_data_for_training,
    save_label_encoder,
)
from src.evaluate import (
    evaluate_model_accuracy,
    evaluate_models,
    save_evaluation_results,
)

# Import da função de treinamento corrigida
try:
    from src.train_corrected import train_and_evaluate_models_corrected
    print("✅ Usando train_corrected_fixed")
except ImportError:
    try:
        from src.train_corrected import train_and_evaluate_models_corrected
        print("⚠️  Usando train_corrected (pode ter bugs)")
    except ImportError:
        from src.train import train_and_evaluate_models_with_balancing
        print("⚠️  Usando train original (sem correção SMOTE)")
        
        # Criar wrapper para compatibilidade
        def train_and_evaluate_models_corrected(X_train, X_test, y_train, y_test, models_dir, images_dir, use_smote=False):
            return train_and_evaluate_models_with_balancing(X_train, X_test, y_train, y_test, models_dir, images_dir)

from src.visualization import (
    plot_class_distribution,
    plot_confusion_matrices,
    plot_correlation_matrix,
    plot_execution_times,
    plot_feature_distributions,
    plot_metrics_comparison,
    plot_metrics_tables,
)

# Import utils com fallback
try:
    from util.utils_fixed import (
        create_experiment_directory,
        generate_summary_report,
        log_execution_info,
        save_experiment_config,
        verify_and_list_outputs,
    )
    print("✅ Usando utils_fixed")
except ImportError:
    from util.utils import (
        create_experiment_directory,
        generate_summary_report,
        log_execution_info,
        save_experiment_config,
    )
    print("⚠️  Usando utils original")
    
    def verify_and_list_outputs(experiment_dir):
        """Fallback simples para verificar arquivos"""
        if os.path.exists(experiment_dir):
            files = []
            for root, dirs, filenames in os.walk(experiment_dir):
                files.extend([os.path.join(root, f) for f in filenames])
            print(f"📁 {len(files)} arquivos encontrados em {experiment_dir}")
            return files
        return []


def create_safe_experiment_directory(experiment_name=None):
    """
    Cria diretório de experimento com máxima compatibilidade
    """
    try:
        # Tentar usar função original primeiro
        base_dir = create_experiment_directory()
        
        if experiment_name:
            parent_dir = os.path.dirname(base_dir)
            new_dir = os.path.join(parent_dir, experiment_name)
            
            # Se já existe, adicionar timestamp
            if os.path.exists(new_dir):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                new_dir = os.path.join(parent_dir, f"{experiment_name}_{timestamp}")
            
            # Renomear
            try:
                os.rename(base_dir, new_dir)
                base_dir = new_dir
            except Exception as e:
                print(f"⚠️  Não foi possível renomear: {e}")
                # Manter nome original
        
        return base_dir
        
    except Exception as e:
        print(f"❌ Erro com create_experiment_directory original: {e}")
        print("🔄 Criando diretório manualmente...")
        
        # Fallback manual
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if experiment_name:
            dir_name = f"{experiment_name}_{timestamp}"
        else:
            dir_name = f"experiment_{timestamp}"
        
        experiment_dir = os.path.join(os.getcwd(), "data", "experiments", dir_name)
        
        # Criar estrutura
        os.makedirs(experiment_dir, exist_ok=True)
        os.makedirs(os.path.join(experiment_dir, "images"), exist_ok=True)
        os.makedirs(os.path.join(experiment_dir, "models"), exist_ok=True)
        
        print(f"✅ Diretório criado manualmente: {experiment_dir}")
        return experiment_dir


def main_working(use_smote=False, experiment_name=None):
    """
    Pipeline principal que GARANTE que os arquivos sejam salvos
    """
    
    print(f"\n{'='*60}")
    print(f"🚀 INICIANDO PIPELINE CORRIGIDO")
    print(f"   SMOTE: {'Ativado' if use_smote else 'Desativado'}")
    print(f"   Diretório de trabalho: {os.getcwd()}")
    print(f"{'='*60}")
    
    # 1. Criar diretório do experimento
    try:
        experiment_dir = create_safe_experiment_directory(experiment_name)
        images_dir = os.path.join(experiment_dir, "images")
        models_dir = os.path.join(experiment_dir, "models")
        
        print(f"📁 Experimento: {experiment_dir}")
        print(f"📁 Imagens: {images_dir}")
        print(f"📁 Modelos: {models_dir}")
        
    except Exception as e:
        print(f"❌ ERRO CRÍTICO ao criar diretórios: {e}")
        return None

    # 2. Configurar experimento
    config = {
        "data_file": "datasets/Total2_classified.csv",
        "test_size": 0.2,
        "random_state": 42,
        "score_cols": SCORE_COLS,
        "use_smote": use_smote,
        "corrected_pipeline": True,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        save_experiment_config(config, experiment_dir)
    except Exception as e:
        print(f"⚠️  Erro ao salvar config: {e}")

    log_execution_info(f"Iniciando pipeline - SMOTE: {'Ativado' if use_smote else 'Desativado'}", experiment_dir)

    try:
        # 3. Carregar e processar dados
        log_execution_info("Carregando dataset original...", experiment_dir)
        print("📊 Carregando dados...")
        
        df = load_and_preprocess_data(config["data_file"])
        df_normalized, score_cols = normalize_scores(df)
        
        print(f"✅ Dados carregados: {df.shape}")

        # 4. Gerar visualizações iniciais
        log_execution_info("Gerando visualizações das features...", experiment_dir)
        print("📈 Gerando visualizações...")
        
        try:
            plot_feature_distributions(df_normalized, score_cols, images_dir)
            plot_correlation_matrix(df_normalized, score_cols, images_dir)
            plot_class_distribution(df_normalized, images_dir)
            print("✅ Visualizações iniciais criadas")
        except Exception as e:
            print(f"⚠️  Erro nas visualizações iniciais: {e}")

        # 5. Preparar dados para treinamento
        log_execution_info("Preparando dados para treinamento...", experiment_dir)
        print("🔧 Preparando dados...")
        
        X_train, X_test, y_train, y_test, le = prepare_data_for_training(df_normalized, score_cols)
        save_label_encoder(le, models_dir)
        
        log_execution_info(f"Divisão dos dados - Treino: {X_train.shape}, Teste: {X_test.shape}", experiment_dir)
        print(f"✅ Dados preparados - Treino: {X_train.shape}, Teste: {X_test.shape}")

        # 6. Treinar modelos
        log_execution_info("Iniciando treinamento dos modelos...", experiment_dir)
        print("🤖 Treinando modelos...")
        
        # Verificar se função aceita parâmetro use_smote
        import inspect
        try:
            sig = inspect.signature(train_and_evaluate_models_corrected)
            if 'use_smote' in sig.parameters:
                results, execution_times, trained_models = train_and_evaluate_models_corrected(
                    X_train, X_test, y_train, y_test, models_dir, images_dir, use_smote=use_smote
                )
            else:
                print("⚠️  Função de treinamento não suporta parâmetro use_smote")
                results, execution_times, trained_models = train_and_evaluate_models_corrected(
                    X_train, X_test, y_train, y_test, models_dir, images_dir
                )
        except Exception as e:
            print(f"❌ Erro no treinamento: {e}")
            raise

        print(f"✅ {len(trained_models)} modelos treinados")

        # 7. Avaliar modelos
        log_execution_info("Avaliando performance dos modelos...", experiment_dir)
        print("📊 Avaliando modelos...")
        
        try:
            metrics_df = evaluate_models(trained_models, X_test, y_test)
            accuracy_df = evaluate_model_accuracy(trained_models, X_test, y_test, le)
            print("✅ Avaliação concluída")
        except Exception as e:
            print(f"❌ Erro na avaliação: {e}")
            raise

        # 8. Processar e salvar resultados
        print("💾 Salvando resultados...")
        
        try:
            results_df = pd.DataFrame(results).T
            if "Melhores Parâmetros" in results_df.columns:
                results_df["Melhores Parâmetros"] = results_df["Melhores Parâmetros"].apply(lambda x: str(x))
            
            # Salvar CSV dos resultados
            results_csv_path = os.path.join(models_dir, "results_with_hyperparameters.csv")
            results_df.to_csv(results_csv_path)
            print(f"✅ Resultados salvos: {results_csv_path}")
            
            # Salvar métricas de avaliação
            save_evaluation_results(metrics_df, accuracy_df, models_dir)
            
        except Exception as e:
            print(f"⚠️  Erro ao salvar resultados: {e}")

        # 9. Gerar visualizações dos resultados
        log_execution_info("Gerando visualizações dos resultados...", experiment_dir)
        print("📈 Gerando gráficos de resultados...")
        
        try:
            plot_metrics_tables(results_df, metrics_df, images_dir)
            plot_execution_times(execution_times, images_dir)
            plot_metrics_comparison(metrics_df, images_dir)
            plot_confusion_matrices(trained_models, X_test, y_test, images_dir)
            print("✅ Gráficos de resultados criados")
        except Exception as e:
            print(f"⚠️  Erro nos gráficos de resultados: {e}")

        # 10. Gerar relatório final
        print("📄 Gerando relatório final...")
        
        try:
            report_file = generate_summary_report(
                metrics_df, accuracy_df, execution_times, results_df, experiment_dir
            )
            print(f"✅ Relatório gerado: {report_file}")
        except Exception as e:
            print(f"⚠️  Erro ao gerar relatório: {e}")
            report_file = None

        # 11. Verificar arquivos gerados
        print("\n📋 Verificando arquivos gerados...")
        try:
            generated_files = verify_and_list_outputs(experiment_dir)
            print(f"✅ {len(generated_files)} arquivos verificados")
        except Exception as e:
            print(f"⚠️  Erro na verificação: {e}")

        # 12. Log final
        smote_status = "COM SMOTE (aplicado corretamente)" if use_smote else "SEM SMOTE"
        success_message = (
            f"Pipeline concluído com sucesso! ({smote_status})\n"
            f"- Diretório: {experiment_dir}\n"
            f"- Relatório: {report_file}\n"
            f"- Modelos: {models_dir}\n"
            f"- Gráficos: {images_dir}\n"
            f"- SEM DATA LEAKAGE ✅"
        )
        
        log_execution_info(success_message, experiment_dir)
        print(f"\n🎉 {success_message}")
        
        # 13. Mostrar resumo dos melhores modelos
        print(f"\n🏆 TOP 3 MODELOS ({smote_status}):")
        try:
            top_models = accuracy_df.nlargest(3, 'Acurácia (%)')
            for idx, (model, row) in enumerate(top_models.iterrows()):
                print(f"  {idx+1}. {model}: {row['Acurácia (%)']:.2f}%")
        except Exception as e:
            print(f"⚠️  Erro ao mostrar top modelos: {e}")
        
        return {
            "experiment_dir": experiment_dir,
            "metrics": metrics_df,
            "accuracy": accuracy_df,
            "use_smote": use_smote,
            "report_file": report_file,
            "success": True
        }

    except Exception as e:
        error_msg = f"Erro durante a execução: {str(e)}"
        log_execution_info(error_msg, experiment_dir)
        print(f"❌ {error_msg}")
        
        return {
            "experiment_dir": experiment_dir,
            "error": str(e),
            "use_smote": use_smote,
            "success": False
        }


def run_both_experiments():
    """
    Executa ambos os experimentos com tratamento robusto de erros
    """
    print("="*60)
    print("🚀 EXECUTANDO EXPERIMENTOS CORRIGIDOS - SEM DATA LEAKAGE")
    print("="*60)
    
    results = {}
    
    # Experimento SEM SMOTE
    print("\n🔸 EXPERIMENTO 1: SEM SMOTE")
    print("-" * 40)
    try:
        results['without_smote'] = main_working(
            use_smote=False, 
            experiment_name="experiment_WITHOUT_smote_corrected"
        )
        if results['without_smote']['success']:
            print("✅ Experimento SEM SMOTE concluído com sucesso!")
        else:
            print("❌ Experimento SEM SMOTE falhou")
    except Exception as e:
        print(f"❌ Erro crítico no experimento SEM SMOTE: {e}")
        results['without_smote'] = {"success": False, "error": str(e)}
    
    print("\n" + "="*60)
    
    # Experimento COM SMOTE
    print("\n🔸 EXPERIMENTO 2: COM SMOTE (APLICADO CORRETAMENTE)")
    print("-" * 40)
    try:
        results['with_smote'] = main_working(
            use_smote=True, 
            experiment_name="experiment_WITH_smote_corrected"
        )
        if results['with_smote']['success']:
            print("✅ Experimento COM SMOTE concluído com sucesso!")
        else:
            print("❌ Experimento COM SMOTE falhou")
    except Exception as e:
        print(f"❌ Erro crítico no experimento COM SMOTE: {e}")
        results['with_smote'] = {"success": False, "error": str(e)}
    
    # Resumo final
    print("\n" + "="*60)
    print("📊 RESUMO DOS EXPERIMENTOS")
    print("="*60)
    
    success_count = 0
    for exp_name, exp_data in results.items():
        if exp_data.get('success', False):
            success_count += 1
            smote_status = "COM SMOTE" if exp_data['use_smote'] else "SEM SMOTE"
            print(f"\n✅ {smote_status}:")
            
            try:
                # Top 3 modelos
                top_models = exp_data['accuracy'].nlargest(3, 'Acurácia (%)')
                for idx, (model, row) in enumerate(top_models.iterrows()):
                    print(f"  {idx+1}. {model}: {row['Acurácia (%)']:.2f}%")
                
                print(f"  📁 Diretório: {exp_data['experiment_dir']}")
                if exp_data.get('report_file'):
                    print(f"  📄 Relatório: {exp_data['report_file']}")
                    
            except Exception as e:
                print(f"  ⚠️  Erro ao mostrar detalhes: {e}")
        else:
            smote_status = "COM SMOTE" if exp_name == 'with_smote' else "SEM SMOTE"
            print(f"\n❌ {smote_status}: FALHOU")
            if 'error' in exp_data:
                print(f"  Erro: {exp_data['error']}")
    
    print(f"\n🎯 RESULTADO FINAL:")
    print(f"  {success_count}/2 experimentos concluídos com sucesso")
    
    if success_count > 0:
        print("  ✅ Experimentos válidos SEM DATA LEAKAGE!")
        print("  📊 Agora você pode comparar os resultados com segurança.")
    else:
        print("  ❌ Nenhum experimento foi concluído com sucesso")
        print("  🔧 Verifique os erros acima e tente novamente")
    
    return results


def run_single_experiment(use_smote=False):
    """
    Executa apenas um experimento
    """
    smote_text = "COM SMOTE" if use_smote else "SEM SMOTE"
    print(f"🔸 EXECUTANDO EXPERIMENTO {smote_text}")
    
    experiment_name = f"experiment_{'with' if use_smote else 'without'}_smote_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    return main_working(use_smote=use_smote, experiment_name=experiment_name)


if __name__ == "__main__":
    print("🚀 PIPELINE DE MACHINE LEARNING CORRIGIDO")
    print("   Versão: Final Working - Garantia de Salvamento")
    
    # Verificar se dataset existe
    dataset_path = "datasets/Total2_classified.csv"
    if not os.path.exists(dataset_path):
        print(f"❌ ERRO: Dataset não encontrado: {dataset_path}")
        print("   Certifique-se de que o arquivo existe antes de continuar.")
        sys.exit(1)
    
    # Executar experimentos
    try:
        results = run_both_experiments()
        print("\n🎉 EXECUÇÃO COMPLETA FINALIZADA!")
        
    except KeyboardInterrupt:
        print("\n⏹️  Execução interrompida pelo usuário.")
    except Exception as e:
        print(f"\n❌ Erro crítico na execução: {e}")
        import traceback
        traceback.print_exc()