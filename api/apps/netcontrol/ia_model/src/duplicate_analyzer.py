import pandas as pd
import numpy as np
import logging


def analyze_duplicates(csv_path):
    """
    Analyze and identify duplicate rows in the dataset
    
    Args:
        csv_path (str): Path to the CSV file
        
    Returns:
        tuple: (dataframe, list of duplicate indices)
    """
    logger = logging.getLogger(__name__)
    
    # Load the dataset
    df = pd.read_csv(csv_path)
    logger.info(f"Dataset loaded: {df.shape}")
    
    # Basic information
    logger.info(f"Total rows: {len(df)}")
    logger.info(f"Total columns: {len(df.columns)}")
    logger.info(f"Columns: {list(df.columns)}")
    
    # Check data types
    logger.info("Data types:")
    for col, dtype in df.dtypes.items():
        logger.info(f"  {col}: {dtype}")
    
    # Check null values
    null_counts = df.isnull().sum()
    total_nulls = null_counts.sum()
    if total_nulls > 0:
        logger.warning(f"Total null values found: {total_nulls}")
        for col, count in null_counts[null_counts > 0].items():
            logger.warning(f"  {col}: {count} null values")
    else:
        logger.info("No null values found")
    
    # Check for complete duplicates (all columns)
    duplicates_mask = df.duplicated()
    num_duplicates = duplicates_mask.sum()
    
    logger.info(f"Complete duplicate rows: {num_duplicates}")
    
    duplicate_indices = []
    if num_duplicates > 0:
        duplicate_indices = df[duplicates_mask].index.tolist()
        logger.warning(f"Duplicate row indices: {duplicate_indices[:10]}..." if len(duplicate_indices) > 10 else f"Duplicate row indices: {duplicate_indices}")
        
        # Find duplicate groups
        df_with_group = df.copy()
        df_with_group['duplicate_group'] = df.groupby(df.columns.tolist()).ngroup()
        
        group_counts = df_with_group['duplicate_group'].value_counts()
        duplicate_groups = group_counts[group_counts > 1]
        
        if len(duplicate_groups) > 0:
            logger.info(f"Found {len(duplicate_groups)} groups of duplicate rows")
            
            for idx, (group_id, count) in enumerate(duplicate_groups.head(3).items(), 1):
                group_rows = df_with_group[df_with_group['duplicate_group'] == group_id]
                logger.info(f"Group {idx}: {count} identical rows (indices: {group_rows.index.tolist()})")
    
    # Check duplicates by IP (if IP column exists)
    ip_columns = [col for col in df.columns if 'ip' in col.lower()]
    if ip_columns:
        logger.info("IP address duplicate analysis:")
        for ip_col in ip_columns:
            ip_duplicates = df[ip_col].duplicated().sum()
            logger.info(f"  {ip_col}: {ip_duplicates} duplicate IPs")
            
            if ip_duplicates > 0:
                duplicate_ips = df[df[ip_col].duplicated()][ip_col].head(5)
                logger.warning(f"    Examples: {duplicate_ips.tolist()}")
    
    # Check class distribution (if classification column exists)
    classification_cols = [col for col in df.columns if any(term in col.lower() for term in ['classif', 'class', 'label'])]
    
    if classification_cols:
        logger.info("Class distribution analysis:")
        for class_col in classification_cols:
            class_dist = df[class_col].value_counts()
            logger.info(f"  Column '{class_col}':")
            for class_name, count in class_dist.items():
                percentage = count / len(df) * 100
                logger.info(f"    {class_name}: {count} ({percentage:.1f}%)")
    
    # Numeric columns statistics
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        logger.info("Numeric columns summary:")
        stats = df[numeric_cols].describe()
        for col in numeric_cols[:5]:  # Show stats for first 5 numeric columns
            logger.info(f"  {col}: min={stats.loc['min', col]:.2f}, max={stats.loc['max', col]:.2f}, mean={stats.loc['mean', col]:.2f}")
    
    return df, duplicate_indices


def create_clean_dataset(csv_path, output_path=None):
    """
    Create a clean version of the dataset without duplicates
    
    Args:
        csv_path (str): Path to input CSV file
        output_path (str): Path to output CSV file (optional)
        
    Returns:
        pd.DataFrame: Cleaned dataset
    """
    logger = logging.getLogger(__name__)
    
    df = pd.read_csv(csv_path)
    original_len = len(df)
    
    logger.info(f"Original dataset: {original_len} rows")
    logger.info(f"Columns: {list(df.columns)}")
    
    # Remove null values
    null_before = df.isnull().sum().sum()
    if null_before > 0:
        logger.warning(f"Null values found: {null_before}")
        df_clean = df.dropna()
        logger.info(f"After removing nulls: {len(df_clean)} rows")
    else:
        df_clean = df.copy()
        logger.info("No null values found")
    
    # Remove duplicates
    duplicates_before = df_clean.duplicated().sum()
    if duplicates_before > 0:
        logger.warning(f"Duplicates found: {duplicates_before}")
        df_clean = df_clean.drop_duplicates()
        logger.info(f"After removing duplicates: {len(df_clean)} rows")
    else:
        logger.info("No duplicates found")
    
    final_len = len(df_clean)
    total_removed = original_len - final_len
    
    logger.info("Cleaning summary:")
    logger.info(f"  Original: {original_len} rows")
    logger.info(f"  Cleaned: {final_len} rows")
    logger.info(f"  Removed: {total_removed} rows ({total_removed/original_len*100:.1f}%)")
    
    if output_path:
        df_clean.to_csv(output_path, index=False)
        logger.info(f"Clean dataset saved to: {output_path}")
    
    return df_clean


def analyze_data_quality(df):
    """
    Analyze the overall data quality
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    logger = logging.getLogger(__name__)
    
    logger.info("Data quality analysis:")
    
    # Check for suspicious value ranges
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    
    for col in numeric_cols:
        col_data = df[col]
        logger.info(f"Column: {col}")
        logger.info(f"  Range: [{col_data.min():.2f}, {col_data.max():.2f}]")
        logger.info(f"  Mean: {col_data.mean():.2f}")
        logger.info(f"  Unique values: {col_data.nunique()}")
        
        # Check for outliers using IQR method
        if col_data.nunique() > 1:
            q1 = col_data.quantile(0.25)
            q3 = col_data.quantile(0.75)
            iqr = q3 - q1
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            outliers = col_data[(col_data < lower_bound) | (col_data > upper_bound)]
            if len(outliers) > 0:
                logger.warning(f"  Outliers detected: {len(outliers)} ({len(outliers)/len(col_data)*100:.1f}%)")