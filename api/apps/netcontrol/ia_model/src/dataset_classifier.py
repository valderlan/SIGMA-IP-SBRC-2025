import logging
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score


class WeightedVotingClassifier:
    """Classifier using true weighted voting"""
    
    def __init__(self):
        self.feature_ranges = {
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
        self.inverse_features = ["virustotal_reputation", "virustotal_harmless"]
        self.optimal_weights = None
        self.logger = logging.getLogger(__name__)
        
    def preprocess_data(self, df):
        """Preprocess the data"""
        self.logger.info("Preprocessing data...")
        
        df_processed = df.copy()
        
        if 'risk_recommended_pulsedive' in df_processed.columns:
            risk_mapping = {
                'none': 1, 'unknown': 2, 'low': 3,
                'medium': 4, 'high': 5, 'critical': 6
            }
            df_processed['risk_recommended_pulsedive'] = df_processed['risk_recommended_pulsedive'].map(risk_mapping)
            df_processed['risk_recommended_pulsedive'] = df_processed['risk_recommended_pulsedive'].fillna(2)
        
        fill_strategies = {
            'abuseipdb_confidence_score': 0,
            'abuseipdb_total_reports': 0,
            'abuseipdb_num_distinct_users': 0,
            'ipvoid_detection_count': 0,
            'virustotal_reputation': 0,
            'virustotal_harmless': 0,
            'virustotal_malicious': 0,
            'virustotal_undetected': 0,
            'virustotal_suspicious': 0
        }
        
        for col, fill_value in fill_strategies.items():
            if col in df_processed.columns:
                df_processed[col] = df_processed[col].fillna(fill_value)
        

        for col in df_processed.columns:
            if df_processed[col].dtype == 'object' and col not in ['ip_address', 'risk_recommended_pulsedive']:
                df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce').fillna(0)
        
        self.logger.info(f"Data preprocessed: {df_processed.shape[0]} rows")
        return df_processed
    
    def normalize_features(self, df):
        """Normalize features to [0,1] with proper inversion handling"""
        self.logger.info("Normalizing features...")
        
        df_norm = df.copy()
        
        for feature, (min_val, max_val) in self.feature_ranges.items():
            if feature in df_norm.columns:

                df_norm[feature] = (df_norm[feature] - min_val) / (max_val - min_val)
                df_norm[feature] = df_norm[feature].clip(0, 1)
                
                if feature in self.inverse_features:
                    df_norm[feature] = 1 - df_norm[feature]
                    self.logger.info(f"Feature {feature} inverted (higher normalized value = allowlist)")
        
        self.logger.info("Normalization completed")
        return df_norm
    
    def vote_abuseipdb(self, row):
        """Vote from AbuseIPDB source"""
        confidence = row.get('abuseipdb_confidence_score', 0)
        
        if confidence >= 0.8:  
            return 'denylist'
        elif confidence <= 0.2:  
            return 'allowlist'
        else:
            return 'suspicious'
    
    def vote_virustotal(self, row):
        """Vote from VirusTotal source - CORRECTED for inverted features"""
        malicious = row.get('virustotal_malicious', 0)
        harmless = row.get('virustotal_harmless', 0)  
        reputation = row.get('virustotal_reputation', 0)  
        
        if malicious >= 0.25:  
            return 'denylist'
        elif harmless <= 0.4 and malicious == 0:  
            return 'allowlist'
        elif reputation <= 0.3 and malicious == 0:  
            return 'allowlist'
        else:
            return 'suspicious'
    
    def vote_ipvoid(self, row):
        """Vote from IPVoid source"""
        detections = row.get('ipvoid_detection_count', 0)
        
        if detections >= 0.25:  
            return 'denylist'
        elif detections == 0:
            return 'allowlist'
        else:
            return 'suspicious'
    
    def vote_pulsedive(self, row):
        """Vote from Pulsedive source"""
        risk = row.get('risk_recommended_pulsedive', 0)
        
        if risk >= 0.8:  
            return 'denylist'
        elif risk <= 0.4:  
            return 'allowlist'
        else:
            return 'suspicious'
    
    def calculate_source_performance(self, df_norm, ground_truth):
        """Calculate individual performance of each source"""
        self.logger.info("Analyzing individual source performance...")
        
        sources = {
            'abuseipdb': self.vote_abuseipdb,
            'virustotal': self.vote_virustotal,
            'ipvoid': self.vote_ipvoid,
            'pulsedive': self.vote_pulsedive
        }
        
        performance_scores = {}
        
        for source_name, vote_func in sources.items():
            predictions = []
            
            for _, row in df_norm.iterrows():
                vote = vote_func(row)
                predictions.append(vote)
            
            accuracy = accuracy_score(ground_truth, predictions)
            performance_scores[source_name] = accuracy
            
            self.logger.info(f"{source_name:15s}: {accuracy:.3f}")
        
        return performance_scores
    
    def calculate_correlation_weights(self, df_norm, ground_truth):
        """Calculate weights based on correlation with ground truth"""
        self.logger.info("Calculating correlation weights...")
        
        class_mapping = {'allowlist': 0, 'suspicious': 1, 'denylist': 2}
        y_encoded = [class_mapping[gt] for gt in ground_truth]
        
        correlations = {}
        
        corr_abuse = abs(np.corrcoef(df_norm['abuseipdb_confidence_score'], y_encoded)[0,1])
        correlations['abuseipdb'] = corr_abuse
        
        vt_combined = (df_norm['virustotal_malicious'] + 
                      (1 - df_norm['virustotal_harmless']) + 
                      (1 - df_norm['virustotal_reputation'])) / 3
        corr_vt = abs(np.corrcoef(vt_combined, y_encoded)[0,1])
        correlations['virustotal'] = corr_vt
        
        corr_ipvoid = abs(np.corrcoef(df_norm['ipvoid_detection_count'], y_encoded)[0,1])
        correlations['ipvoid'] = corr_ipvoid
        
        corr_pulse = abs(np.corrcoef(df_norm['risk_recommended_pulsedive'], y_encoded)[0,1])
        correlations['pulsedive'] = corr_pulse
        
        self.logger.info("Correlations calculated:")
        for source, corr in correlations.items():
            self.logger.info(f"  {source:15s}: {corr:.3f}")
        
        return correlations
    
    def calculate_consensus_weights(self, df_norm, ground_truth):
        """Calculate weights based on consensus between sources"""
        self.logger.info("Calculating consensus weights...")
        
        sources = {
            'abuseipdb': self.vote_abuseipdb,
            'virustotal': self.vote_virustotal,
            'ipvoid': self.vote_ipvoid,
            'pulsedive': self.vote_pulsedive
        }
        
        all_votes = {}
        for source_name, vote_func in sources.items():
            votes = []
            for _, row in df_norm.iterrows():
                votes.append(vote_func(row))
            all_votes[source_name] = votes
        
        consensus_scores = {}
        
        for source_name in sources.keys():
            agreements = 0
            total_comparisons = 0
            
            for i in range(len(ground_truth)):
                source_vote = all_votes[source_name][i]
                true_class = ground_truth[i]
                
                for other_source in sources.keys():
                    if other_source != source_name:
                        other_vote = all_votes[other_source][i]
                        
                        if (source_vote == true_class and other_vote == true_class):
                            agreements += 1
                        total_comparisons += 1
            
            consensus_score = agreements / total_comparisons if total_comparisons > 0 else 0
            consensus_scores[source_name] = consensus_score
            
            self.logger.info(f"{source_name:15s}: {consensus_score:.3f}")
        
        return consensus_scores
    
    def determine_optimal_weights(self, df_norm, ground_truth):
        """Determine optimal weights combining multiple analyses - TRUE WEIGHTED VOTING"""
        self.logger.info("Determining optimal weights...")
        
        performance_scores = self.calculate_source_performance(df_norm, ground_truth)
        
        correlation_scores = self.calculate_correlation_weights(df_norm, ground_truth)
        
        consensus_scores = self.calculate_consensus_weights(df_norm, ground_truth)
        
        sources = ['abuseipdb', 'virustotal', 'ipvoid', 'pulsedive']
        combined_weights = {}
        
        self.logger.info("DETAILED WEIGHT CALCULATION:")
        self.logger.info("=" * 60)
        
        for source in sources:

            perf_contrib = performance_scores[source] * 0.5
            corr_contrib = correlation_scores[source] * 0.3
            cons_contrib = consensus_scores[source] * 0.2
            
            combined_score = perf_contrib + corr_contrib + cons_contrib
            combined_weights[source] = combined_score
            
            self.logger.info(f"{source:15s}:")
            self.logger.info(f"  Performance: {performance_scores[source]:.3f} × 0.5 = {perf_contrib:.3f}")
            self.logger.info(f"  Correlation: {correlation_scores[source]:.3f} × 0.3 = {corr_contrib:.3f}")
            self.logger.info(f"  Consensus:   {consensus_scores[source]:.3f} × 0.2 = {cons_contrib:.3f}")
            self.logger.info(f"  TOTAL:      {combined_score:.3f}")
            self.logger.info("")
        
        total_weight = sum(combined_weights.values())
        self.logger.info(f"Total weight sum: {total_weight:.3f}")
        self.logger.info("Normalizing to sum 1.0:")
        
        optimal_weights = {}
        for source, weight in combined_weights.items():
            normalized_weight = weight / total_weight
            optimal_weights[source] = normalized_weight
            self.logger.info(f"  {source:15s}: {weight:.3f} / {total_weight:.3f} = {normalized_weight:.3f}")
        
        self.logger.info("=" * 60)
        self.logger.info("FINAL OPTIMIZED WEIGHTS:")
        for source, weight in optimal_weights.items():
            self.logger.info(f"  {source:15s}: {weight:.3f}")
        
        total_check = sum(optimal_weights.values())
        self.logger.info(f"Verification (should be 1.0): {total_check:.3f}")
        
        self.optimal_weights = optimal_weights
        return optimal_weights
    
    def create_ground_truth(self, df_processed):
        """Create ground truth based on hierarchical rules"""
        self.logger.info("Creating ground truth...")
        
        ground_truth = []
        
        rule_counts = {
            'rule_1_abuse_high': 0,
            'rule_2_abuse_vt_ipvoid': 0,
            'rule_3_vt_ipvoid_high': 0,
            'rule_4_pulsedive_high': 0,
            'rule_5_allowlist_clean': 0,
            'rule_6_allowlist_reputation': 0,
            'rule_7_allowlist_all_clean': 0,
            'rule_8_suspicious_default': 0
        }
        
        abuse_conf_stats = df_processed['abuseipdb_confidence_score'].describe()
        self.logger.info("MAIN FEATURE ANALYSIS:")
        self.logger.info(f"AbuseIPDB Confidence Score - Statistics:")
        self.logger.info(f"  Mean: {abuse_conf_stats['mean']:.1f}")
        self.logger.info(f"  Median: {abuse_conf_stats['50%']:.1f}")
        self.logger.info(f"  Max: {abuse_conf_stats['max']:.1f}")
        self.logger.info(f"  Min: {abuse_conf_stats['min']:.1f}")
        
        abuse_100 = (df_processed['abuseipdb_confidence_score'] == 100).sum()
        abuse_95_plus = (df_processed['abuseipdb_confidence_score'] >= 95).sum()
        abuse_0 = (df_processed['abuseipdb_confidence_score'] == 0).sum()
        
        self.logger.info(f"  IPs with confidence = 100: {abuse_100} ({abuse_100/len(df_processed)*100:.1f}%)")
        self.logger.info(f"  IPs with confidence >= 95: {abuse_95_plus} ({abuse_95_plus/len(df_processed)*100:.1f}%)")
        self.logger.info(f"  IPs with confidence = 0: {abuse_0} ({abuse_0/len(df_processed)*100:.1f}%)")
        
        for _, row in df_processed.iterrows():
            abuse_conf = row.get('abuseipdb_confidence_score', 0)
            abuse_reports = row.get('abuseipdb_total_reports', 0)
            
            vt_malicious = row.get('virustotal_malicious', 0)
            vt_harmless = row.get('virustotal_harmless', 0)
            vt_reputation = row.get('virustotal_reputation', 0)
            
            ipvoid_det = row.get('ipvoid_detection_count', 0)
            pulsedive_risk = row.get('risk_recommended_pulsedive', 2)
            
            if (abuse_conf >= 95 and abuse_reports >= 10):
                ground_truth.append('denylist')
                rule_counts['rule_1_abuse_high'] += 1

            elif (abuse_conf >= 85 and vt_malicious >= 5 and ipvoid_det >= 5):
                ground_truth.append('denylist')
                rule_counts['rule_2_abuse_vt_ipvoid'] += 1

            elif (vt_malicious >= 10 and ipvoid_det >= 15):
                ground_truth.append('denylist')
                rule_counts['rule_3_vt_ipvoid_high'] += 1

            elif (pulsedive_risk >= 5 and abuse_conf >= 70):
                ground_truth.append('denylist')
                rule_counts['rule_4_pulsedive_high'] += 1
            

            elif (abuse_conf <= 5 and vt_malicious == 0 and vt_harmless >= 50):
                ground_truth.append('allowlist')
                rule_counts['rule_5_allowlist_clean'] += 1

            elif (abuse_conf == 0 and vt_malicious == 0 and vt_reputation >= 50):
                ground_truth.append('allowlist')
                rule_counts['rule_6_allowlist_reputation'] += 1

            elif (abuse_conf <= 10 and vt_malicious == 0 and ipvoid_det == 0 and pulsedive_risk <= 2):
                ground_truth.append('allowlist')
                rule_counts['rule_7_allowlist_all_clean'] += 1
            
            else:
                ground_truth.append('suspicious')
                rule_counts['rule_8_suspicious_default'] += 1
        
        gt_counts = pd.Series(ground_truth).value_counts()
        self.logger.info("DISTRIBUTION BY RULE:")
        self.logger.info("=" * 50)
        self.logger.info("DENYLIST RULES:")
        self.logger.info(f"  Rule 1 (abuse_conf>=95 + reports>=10): {rule_counts['rule_1_abuse_high']:4d} ({rule_counts['rule_1_abuse_high']/len(ground_truth)*100:.1f}%)")
        self.logger.info(f"  Rule 2 (abuse>=85 + vt>=5 + ipvoid>=5): {rule_counts['rule_2_abuse_vt_ipvoid']:4d} ({rule_counts['rule_2_abuse_vt_ipvoid']/len(ground_truth)*100:.1f}%)")
        self.logger.info(f"  Rule 3 (vt>=10 + ipvoid>=15):         {rule_counts['rule_3_vt_ipvoid_high']:4d} ({rule_counts['rule_3_vt_ipvoid_high']/len(ground_truth)*100:.1f}%)")
        self.logger.info(f"  Rule 4 (pulsedive>=5 + abuse>=70):    {rule_counts['rule_4_pulsedive_high']:4d} ({rule_counts['rule_4_pulsedive_high']/len(ground_truth)*100:.1f}%)")
        
        self.logger.info("\nALLOWLIST RULES:")
        self.logger.info(f"  Rule 5 (abuse<=5 + vt=0 + harm>=50):   {rule_counts['rule_5_allowlist_clean']:4d} ({rule_counts['rule_5_allowlist_clean']/len(ground_truth)*100:.1f}%)")
        self.logger.info(f"  Rule 6 (abuse=0 + vt=0 + rep>=50):     {rule_counts['rule_6_allowlist_reputation']:4d} ({rule_counts['rule_6_allowlist_reputation']/len(ground_truth)*100:.1f}%)")
        self.logger.info(f"  Rule 7 (abuse<=10 + everything clean): {rule_counts['rule_7_allowlist_all_clean']:4d} ({rule_counts['rule_7_allowlist_all_clean']/len(ground_truth)*100:.1f}%)")
        
        self.logger.info("\nSUSPICIOUS RULE:")
        self.logger.info(f"  Rule 8 (intermediate cases):          {rule_counts['rule_8_suspicious_default']:4d} ({rule_counts['rule_8_suspicious_default']/len(ground_truth)*100:.1f}%)")
        
        self.logger.info("\nFINAL DISTRIBUTION:")
        for class_name, count in gt_counts.items():
            self.logger.info(f"  {class_name:10s}: {count:5d} ({count/len(ground_truth)*100:.1f}%)")
        
        return ground_truth
    
    def classify_with_weighted_voting(self, df_norm, weights):
        """Classify using true weighted voting"""
        self.logger.info("Classifying with weighted voting...")
        
        sources = {
            'abuseipdb': self.vote_abuseipdb,
            'virustotal': self.vote_virustotal,
            'ipvoid': self.vote_ipvoid,
            'pulsedive': self.vote_pulsedive
        }
        
        predictions = []
        confidence_scores = []
        
        vote_analysis = {
            'unanimous_denylist': 0,
            'unanimous_allowlist': 0,
            'unanimous_suspicious': 0,
            'majority_denylist': 0,
            'majority_allowlist': 0,
            'majority_suspicious': 0,
            'tie_scenarios': 0
        }
        
        self.logger.info("VOTING PROCESS ANALYSIS:")
        self.logger.info("=" * 50)
        
        for i, (_, row) in enumerate(df_norm.iterrows()):

            votes = {}
            for source_name, vote_func in sources.items():
                votes[source_name] = vote_func(row)
            
            class_scores = {'allowlist': 0, 'suspicious': 0, 'denylist': 0}
            
            for source_name, vote in votes.items():
                weight = weights[source_name]
                class_scores[vote] += weight
            
            predicted_class = max(class_scores, key=class_scores.get)
            confidence = class_scores[predicted_class]
            
            predictions.append(predicted_class)
            confidence_scores.append(confidence)
            
            vote_list = list(votes.values())
            unique_votes = set(vote_list)
            
            if len(unique_votes) == 1:
                if predicted_class == 'denylist':
                    vote_analysis['unanimous_denylist'] += 1
                elif predicted_class == 'allowlist':
                    vote_analysis['unanimous_allowlist'] += 1
                else:
                    vote_analysis['unanimous_suspicious'] += 1
            elif len(unique_votes) == 2:
                if predicted_class == 'denylist':
                    vote_analysis['majority_denylist'] += 1
                elif predicted_class == 'allowlist':
                    vote_analysis['majority_allowlist'] += 1
                else:
                    vote_analysis['majority_suspicious'] += 1
            else:
                vote_analysis['tie_scenarios'] += 1
            
            if i < 5:
                self.logger.info(f"\nExample {i+1}:")
                self.logger.info(f"  Votes: {votes}")
                self.logger.info(f"  Scores: allowlist={class_scores['allowlist']:.3f}, suspicious={class_scores['suspicious']:.3f}, denylist={class_scores['denylist']:.3f}")
                self.logger.info(f"  Prediction: {predicted_class} (confidence: {confidence:.3f})")
        
        total_votes = len(predictions)
        self.logger.info(f"\nVOTING STATISTICS:")
        self.logger.info(f"  Unanimous Denylist:  {vote_analysis['unanimous_denylist']:4d} ({vote_analysis['unanimous_denylist']/total_votes*100:.1f}%)")
        self.logger.info(f"  Unanimous Allowlist: {vote_analysis['unanimous_allowlist']:4d} ({vote_analysis['unanimous_allowlist']/total_votes*100:.1f}%)")
        self.logger.info(f"  Unanimous Suspicious:{vote_analysis['unanimous_suspicious']:4d} ({vote_analysis['unanimous_suspicious']/total_votes*100:.1f}%)")
        self.logger.info(f"  Majority Denylist:   {vote_analysis['majority_denylist']:4d} ({vote_analysis['majority_denylist']/total_votes*100:.1f}%)")
        self.logger.info(f"  Majority Allowlist:  {vote_analysis['majority_allowlist']:4d} ({vote_analysis['majority_allowlist']/total_votes*100:.1f}%)")
        self.logger.info(f"  Majority Suspicious: {vote_analysis['majority_suspicious']:4d} ({vote_analysis['majority_suspicious']/total_votes*100:.1f}%)")
        self.logger.info(f"  Complex Scenarios:   {vote_analysis['tie_scenarios']:4d} ({vote_analysis['tie_scenarios']/total_votes*100:.1f}%)")
        
        conf_high = sum(1 for conf in confidence_scores if conf >= 0.8)
        conf_medium = sum(1 for conf in confidence_scores if 0.5 <= conf < 0.8)
        conf_low = sum(1 for conf in confidence_scores if conf < 0.5)
        
        self.logger.info(f"\nCONFIDENCE ANALYSIS:")
        self.logger.info(f"  High confidence (≥0.8):    {conf_high:4d} ({conf_high/total_votes*100:.1f}%)")
        self.logger.info(f"  Medium confidence (0.5-0.8): {conf_medium:4d} ({conf_medium/total_votes*100:.1f}%)")
        self.logger.info(f"  Low confidence (<0.5):      {conf_low:4d} ({conf_low/total_votes*100:.1f}%)")
        
        return predictions, confidence_scores