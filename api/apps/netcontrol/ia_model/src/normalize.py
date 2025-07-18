import pandas as pd
import pickle
import logging
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.impute import SimpleImputer


def preprocess_ip_dataset(input_file='datasets/dataset_ip_classified.csv', output_file='datasets/dataset_ip_normm.csv'):
    """
    Preprocess the IP dataset for ML model usage
    
    Args:
        input_file (str): Path to input CSV file
        output_file (str): Path to output normalized CSV file
    
    Returns:
        pd.DataFrame: Processed dataset
    """
    logger = logging.getLogger(__name__)
    
    # Load the dataset
    logger.info(f"Loading dataset: {input_file}")
    df = pd.read_csv(input_file)
    
    logger.info(f"Original dataset: {df.shape[0]} rows, {df.shape[1]} columns")
    
    # Display dataset information
    logger.info("Dataset information:")
    logger.info(f"Columns: {list(df.columns)}")
    
    # Check unique values in categorical columns
    if 'risk_recommended_pulsedive' in df.columns:
        risk_values = df['risk_recommended_pulsedive'].value_counts()
        logger.info(f"Unique values in 'risk_recommended_pulsedive': {risk_values.to_dict()}")
    
    if 'classification' in df.columns:
        class_values = df['classification'].value_counts()
        logger.info(f"Unique values in 'classification': {class_values.to_dict()}")
    
    # 1. Remove specified columns
    columns_to_drop = ['confidence_score', 'ground_truth', 'prediction_match']
    df_processed = df.drop(columns=columns_to_drop, errors='ignore')
    
    logger.info(f"After column removal: {df_processed.shape[1]} columns")
    
    # 2. Separate columns by processing type
    # Columns that should not be normalized
    non_normalized_cols = ['ip_address', 'classification']
    
    # Categorical column for encoding
    categorical_col = 'risk_recommended_pulsedive'
    
    # Numerical columns for normalization (WITHOUT risk_recommended_pulsedive yet)
    numerical_cols = [col for col in df_processed.columns 
                     if col not in non_normalized_cols + [categorical_col]]
    
    logger.info(f"Numerical columns for normalization: {numerical_cols}")
    
    # 3. Handle missing values in numerical columns
    if len(numerical_cols) > 0:
        logger.info("Handling missing values in numerical columns...")
        imputer = SimpleImputer(strategy='median')
        df_processed[numerical_cols] = imputer.fit_transform(df_processed[numerical_cols])
    
    # 4. Encode categorical column risk_recommended_pulsedive FIRST
    if categorical_col in df_processed.columns:
        logger.info(f"Encoding categorical column: {categorical_col}")
        
        # Handle missing values in categorical column
        df_processed[categorical_col] = df_processed[categorical_col].fillna('medium')
        
        # Create manual mapping for better interpretability
        risk_mapping = {
            'unknown': 1,
            'none': 2,
            'low': 3,
            'medium': 4,
            'high': 5,
            'critical': 6
        }
        
        # Check for unique values
        unique_values = df_processed[categorical_col].unique()
        logger.info(f"Unique values found: {unique_values}")
        
        # Apply mapping or use LabelEncoder if necessary
        if all(val in risk_mapping.keys() or pd.isna(val) for val in unique_values):
            df_processed[categorical_col] = df_processed[categorical_col].map(risk_mapping)
            logger.info(f"Applied manual mapping: {risk_mapping}")
        else:
            # If there are unexpected values, use LabelEncoder
            le = LabelEncoder()
            df_processed[categorical_col] = le.fit_transform(df_processed[categorical_col].astype(str))
            
            # Save LabelEncoder mapping
            mapping = dict(zip(le.classes_, le.transform(le.classes_)))
            logger.info(f"LabelEncoder mapping: {mapping}")
    
    # 5. Define ranges for MinMaxScaler
    feature_ranges = {
        "abuseipdb_confidence_score": [0, 100],
        "abuseipdb_total_reports": [0, 85000],
        "abuseipdb_num_distinct_users": [0, 2000],
        "ipvoid_detection_count": [0, 93],
        "risk_recommended_pulsedive": [1, 6],
        "virustotal_reputation": [-127, 565],
        "virustotal_harmless": [0, 86],
        "virustotal_malicious": [0, 20],
        "virustotal_undetected": [0, 91],
        "virustotal_suspicious": [0, 5]
    }
    
    # 6. Now include risk_recommended_pulsedive in columns for normalization
    all_numerical_cols = numerical_cols + [categorical_col]
    logger.info(f"All columns for normalization: {all_numerical_cols}")
    
    # 7. Normalize ALL numerical columns using MinMaxScaler with specific ranges
    if len(all_numerical_cols) > 0:
        logger.info("Normalizing all numerical columns with MinMaxScaler...")
        
        # Apply MinMaxScaler for each column with its specific range
        scalers = {}
        for col in all_numerical_cols:
            if col in feature_ranges:
                min_val, max_val = feature_ranges[col]
                scaler = MinMaxScaler(feature_range=(0, 1))
                
                # Reshape to ensure correct format
                values = df_processed[col].values.reshape(-1, 1)
                
                # Fit scaler with known min and max values
                scaler.fit([[min_val], [max_val]])
                
                # Transform actual data
                df_processed[col] = scaler.transform(values).flatten()
                
                # Save scaler
                scalers[col] = {
                    'scaler': scaler,
                    'min_val': min_val,
                    'max_val': max_val
                }
                
                logger.info(f"Column {col}: Range [{min_val}, {max_val}] -> [0, 1]")
            else:
                logger.warning(f"Range not defined for column {col}")
        
        # Save scaler parameters for future use
        scaler_params = {
            'scalers': scalers,
            'columns': all_numerical_cols,
            'feature_ranges': feature_ranges
        }
        
        # Save scaler parameters
        scaler_file = 'scaler_params.pkl'
        with open(scaler_file, 'wb') as f:
            pickle.dump(scaler_params, f)
        
        logger.info(f"Scaler parameters saved to '{scaler_file}'")
    
    # 8. Reorder columns (ip_address, classification, risk_recommended_pulsedive, other columns)
    cols_order = ['ip_address', 'classification', 'risk_recommended_pulsedive'] + numerical_cols
    df_processed = df_processed[cols_order]
    
    # 9. Verify final result
    logger.info(f"Processed dataset: {df_processed.shape[0]} rows, {df_processed.shape[1]} columns")
    logger.info("Descriptive statistics of normalized columns:")
    stats = df_processed[all_numerical_cols].describe()
    for col in all_numerical_cols:
        logger.info(f"  {col}: min={stats.loc['min', col]:.3f}, max={stats.loc['max', col]:.3f}, mean={stats.loc['mean', col]:.3f}")
    
    logger.info(f"Distribution of {categorical_col} (after normalization):")
    dist = df_processed[categorical_col].value_counts().to_dict()
    logger.info(f"  {dist}")
    
    # 10. Save processed dataset
    df_processed.to_csv(output_file, index=False)
    logger.info(f"Dataset saved as: {output_file}")
    
    return df_processed


def apply_preprocessing_to_new_data(new_data_file, scaler_params_file='scaler_params.pkl', 
                                   output_file='new_data_processed.csv'):
    """
    Apply the same preprocessing to new data using saved parameters
    
    Args:
        new_data_file (str): Path to new data CSV file
        scaler_params_file (str): Path to saved scaler parameters
        output_file (str): Path to output processed CSV file
        
    Returns:
        pd.DataFrame: Processed new data
    """
    logger = logging.getLogger(__name__)
    logger.info("Applying preprocessing to new data...")
    
    # Load new data
    df_new = pd.read_csv(new_data_file)
    logger.info(f"New data loaded: {df_new.shape}")
    
    # Load scaler parameters
    with open(scaler_params_file, 'rb') as f:
        scaler_data = pickle.load(f)
    
    scalers = scaler_data['scalers']
    columns = scaler_data['columns']
    feature_ranges = scaler_data['feature_ranges']
    
    # Apply categorical encoding (same mapping)
    risk_mapping = {
        'unknown': 1,
        'none': 2,
        'low': 3,
        'medium': 4,
        'high': 5,
        'critical': 6
    }
    
    if 'risk_recommended_pulsedive' in df_new.columns:
        df_new['risk_recommended_pulsedive'] = df_new['risk_recommended_pulsedive'].fillna('medium')
        df_new['risk_recommended_pulsedive'] = df_new['risk_recommended_pulsedive'].map(risk_mapping)
        logger.info("Applied categorical encoding to new data")
    
    # Apply normalization using saved scalers
    for col in columns:
        if col in scalers and col in df_new.columns:
            scaler_info = scalers[col]
            scaler = scaler_info['scaler']
            
            # Transform data
            values = df_new[col].values.reshape(-1, 1)
            df_new[col] = scaler.transform(values).flatten()
            logger.info(f"Applied normalization to column: {col}")
    
    # Save processed data
    df_new.to_csv(output_file, index=False)
    logger.info(f"New processed data saved as: {output_file}")
    
    return df_new


def validate_normalized_dataset(file_path):
    """
    Validate that the normalized dataset has the correct structure for ML training
    
    Args:
        file_path (str): Path to normalized CSV file
        
    Returns:
        bool: True if validation passes
    """
    logger = logging.getLogger(__name__)
    
    try:
        df = pd.read_csv(file_path)
        logger.info(f"Validating normalized dataset: {file_path}")
        logger.info(f"Dataset shape: {df.shape}")
        
        # Expected columns for ML training
        expected_columns = [
            'ip_address', 'classification', 'risk_recommended_pulsedive',
            'abuseipdb_confidence_score', 'abuseipdb_total_reports',
            'abuseipdb_num_distinct_users', 'ipvoid_detection_count',
            'virustotal_reputation', 'virustotal_harmless',
            'virustotal_malicious', 'virustotal_undetected',
            'virustotal_suspicious'
        ]
        
        # Check for missing columns
        missing_cols = set(expected_columns) - set(df.columns)
        if missing_cols:
            logger.error(f"Missing expected columns: {missing_cols}")
            return False
        
        # Check normalization ranges for numerical columns
        numerical_cols = [col for col in expected_columns if col not in ['ip_address', 'classification']]
        
        for col in numerical_cols:
            if col in df.columns:
                col_min = df[col].min()
                col_max = df[col].max()
                
                # Check if values are in [0, 1] range (allowing small tolerance)
                if col_min < -0.001 or col_max > 1.001:
                    logger.warning(f"Column {col} not properly normalized: range [{col_min:.3f}, {col_max:.3f}]")
                else:
                    logger.info(f"Column {col} properly normalized: range [{col_min:.3f}, {col_max:.3f}]")
        
        # Check classification distribution
        if 'classification' in df.columns:
            class_dist = df['classification'].value_counts()
            logger.info("Classification distribution:")
            for class_name, count in class_dist.items():
                logger.info(f"  {class_name}: {count} ({count/len(df)*100:.1f}%)")
        
        # Check for any remaining null values
        null_counts = df.isnull().sum()
        total_nulls = null_counts.sum()
        if total_nulls > 0:
            logger.warning(f"Found {total_nulls} null values in normalized dataset")
            for col, count in null_counts[null_counts > 0].items():
                logger.warning(f"  {col}: {count} null values")
            return False
        
        logger.info("Dataset validation passed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return False


def get_normalization_info(scaler_params_file='scaler_params.pkl'):
    """
    Get information about the normalization parameters
    
    Args:
        scaler_params_file (str): Path to saved scaler parameters
        
    Returns:
        dict: Normalization information
    """
    logger = logging.getLogger(__name__)
    
    try:
        with open(scaler_params_file, 'rb') as f:
            scaler_data = pickle.load(f)
        
        info = {
            'columns_normalized': scaler_data['columns'],
            'feature_ranges': scaler_data['feature_ranges'],
            'scaler_count': len(scaler_data['scalers'])
        }
        
        logger.info("Normalization information:")
        logger.info(f"  Normalized columns: {len(info['columns_normalized'])}")
        logger.info(f"  Feature ranges defined: {len(info['feature_ranges'])}")
        logger.info(f"  Scalers saved: {info['scaler_count']}")
        
        return info
        
    except FileNotFoundError:
        logger.error(f"Scaler parameters file not found: {scaler_params_file}")
        return None
    except Exception as e:
        logger.error(f"Error reading scaler parameters: {e}")
        return None


def create_feature_summary(normalized_file, output_file='feature_summary.txt'):
    """
    Create a summary of the normalized features for documentation
    
    Args:
        normalized_file (str): Path to normalized dataset
        output_file (str): Path to output summary file
    """
    logger = logging.getLogger(__name__)
    
    try:
        df = pd.read_csv(normalized_file)
        
        with open(output_file, 'w') as f:
            f.write("NORMALIZED DATASET FEATURE SUMMARY\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Dataset: {normalized_file}\n")
            f.write(f"Shape: {df.shape[0]} rows, {df.shape[1]} columns\n")
            f.write(f"Generated: {pd.Timestamp.now()}\n\n")
            
            # Column information
            f.write("COLUMNS:\n")
            f.write("-" * 20 + "\n")
            for i, col in enumerate(df.columns, 1):
                f.write(f"{i:2d}. {col}\n")
            f.write("\n")
            
            # Classification distribution
            if 'classification' in df.columns:
                f.write("CLASSIFICATION DISTRIBUTION:\n")
                f.write("-" * 30 + "\n")
                class_dist = df['classification'].value_counts()
                for class_name, count in class_dist.items():
                    percentage = count / len(df) * 100
                    f.write(f"  {class_name:<12}: {count:5d} ({percentage:5.1f}%)\n")
                f.write("\n")
            
            # Numerical features statistics
            numerical_cols = df.select_dtypes(include=['float64', 'int64']).columns
            if len(numerical_cols) > 0:
                f.write("NUMERICAL FEATURES STATISTICS:\n")
                f.write("-" * 35 + "\n")
                stats = df[numerical_cols].describe()
                
                for col in numerical_cols:
                    f.write(f"\n{col}:\n")
                    f.write(f"  Min:    {stats.loc['min', col]:8.3f}\n")
                    f.write(f"  Max:    {stats.loc['max', col]:8.3f}\n")
                    f.write(f"  Mean:   {stats.loc['mean', col]:8.3f}\n")
                    f.write(f"  Std:    {stats.loc['std', col]:8.3f}\n")
                    f.write(f"  Unique: {df[col].nunique():8d}\n")
            
            # Data quality checks
            f.write("\nDATA QUALITY CHECKS:\n")
            f.write("-" * 25 + "\n")
            
            # Null values
            null_counts = df.isnull().sum()
            total_nulls = null_counts.sum()
            f.write(f"Total null values: {total_nulls}\n")
            
            if total_nulls > 0:
                for col, count in null_counts[null_counts > 0].items():
                    f.write(f"  {col}: {count} nulls\n")
            
            # Duplicate rows
            duplicates = df.duplicated().sum()
            f.write(f"Duplicate rows: {duplicates}\n")
            
            # Normalization check
            f.write("\nNORMALIZATION CHECK:\n")
            f.write("-" * 20 + "\n")
            for col in numerical_cols:
                col_min = df[col].min()
                col_max = df[col].max()
                
                if col_min >= 0 and col_max <= 1:
                    status = "✓ Properly normalized [0,1]"
                else:
                    status = f"✗ Out of range [{col_min:.3f}, {col_max:.3f}]"
                
                f.write(f"  {col:<30}: {status}\n")
        
        logger.info(f"Feature summary created: {output_file}")
        
    except Exception as e:
        logger.error(f"Error creating feature summary: {e}")


# Example usage and testing
if __name__ == "__main__":
    import logging
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    # Test the preprocessing pipeline
    try:
        logger.info("Starting dataset preprocessing test...")
        
        # Process original dataset
        df_processed = preprocess_ip_dataset(
            input_file='datasets/dataset_ip_classified.csv',
            output_file='datasets/dataset_ip_normm.csv'
        )
        
        # Validate the result
        is_valid = validate_normalized_dataset('datasets/dataset_ip_normm.csv')
        
        if is_valid:
            logger.info("✅ Dataset preprocessing completed successfully!")
            
            # Create feature summary
            create_feature_summary('datasets/dataset_ip_normm.csv')
            
            # Get normalization info
            norm_info = get_normalization_info()
            
            logger.info("Generated files:")
            logger.info("  - datasets/dataset_ip_normm.csv: Normalized dataset")
            logger.info("  - scaler_params.pkl: Scaler parameters")
            logger.info("  - feature_summary.txt: Feature documentation")
            
        else:
            logger.error("❌ Dataset validation failed!")
            
    except Exception as e:
        logger.error(f"❌ Error during preprocessing: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
    
    logger.info("Preprocessing test completed.")