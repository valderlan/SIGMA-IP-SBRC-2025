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
            "apivoid_risk_score": [0, 100],
            "apivoid_blacklists_detection_rate": [0, 1.0],
            
            "risk_recommended_pulsedive": [1, 6],
            "virustotal_reputation": [-127, 565],
            "virustotal_harmless": [0, 95],
            "virustotal_malicious": [0, 95],
            "virustotal_undetected": [0, 95],
            "virustotal_suspicious": [0, 95]
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
            'apivoid_risk_score': 0,
            'apivoid_blacklists_detection_rate': 0,
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
            if df_processed[col].dtype == 'object' and col not in ['ip', 'risk_recommended_pulsedive']:
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

        if confidence >= 0.6:  
            return 'denylist'
        elif confidence == 0.0:  
            return 'allowlist'
        else:
            return 'suspicious'
    
    def vote_virustotal(self, row):
        """
        Vote from VirusTotal source based on strict Allowlist rules.
        """
        malicious_norm = row.get('virustotal_malicious', 0)
        undetected_norm = row.get('virustotal_undetected', 0)
        suspicious_norm = row.get('virustotal_suspicious', 0)

        reputation_norm = row.get('virustotal_reputation', 0) 
        harmless_norm = row.get('virustotal_harmless', 0)

        # --- LIMIARES (THRESHOLDS) ---
        
        # 1. Denylist Criteria
        # Malicious > 1 (aprox 0.011)
        THRESH_MALICIOUS_DENY = 0.011
        # Reputation < -7 (Invertido: > 0.826)
        THRESH_REP_DENY = 0.826

        # 2. Allowlist Criteria
        # Reputation > 0 (Invertido: < 0.816)
        THRESH_REP_ALLOW = 0.816
        
        # Harmless > 40 votos (Real). Invertido: 1 - (40/95) = 0.58
        # Queremos "harmless real alto", logo "harmless norm BAIXO"
        THRESH_HARMLESS_HIGH_INV = 0.58
        
        # Undetected > 40 votos (Real). Normal: 40/95 = 0.42
        # Queremos "undetected real alto", logo "undetected norm ALTO"
        THRESH_UNDETECTED_HIGH = 0.42
        
        # 3. Suspicious Criteria
        # Reputation entre -1 e -6
        THRESH_REP_SUSP_MIN = 0.817
        THRESH_REP_SUSP_MAX = 0.826
        THRESH_SUSP_GT_0 = 0.0

        # --- DECISÃO ---

        # 1. DENYLIST
        if malicious_norm > THRESH_MALICIOUS_DENY or reputation_norm > THRESH_REP_DENY:
            return 'denylist'

        # 2. ALLOWLIST
        elif (malicious_norm == 0.0 and 
              reputation_norm < THRESH_REP_ALLOW and 
              harmless_norm < THRESH_HARMLESS_HIGH_INV and 
              undetected_norm > THRESH_UNDETECTED_HIGH):
            return 'allowlist'

        # 3. SUSPICIOUS
        elif (suspicious_norm > THRESH_SUSP_GT_0) or \
             (THRESH_REP_SUSP_MIN <= reputation_norm <= THRESH_REP_SUSP_MAX):
            return 'suspicious'

        return 'suspicious'
    
    def vote_apivoid(self, row):
        """Vote from APIVoid source using normalized values"""
        
        risk_score_norm = row.get('apivoid_risk_score', 0)
        detection_rate_norm = row.get('apivoid_blacklists_detection_rate', 0)

        # Denylist: risk > 60 (0.6) OU rate > 0.02
        if risk_score_norm > 0.6 or detection_rate_norm > 0.02:
            return 'denylist'

        # Allowlist: risk == 0 E rate < 0.01
        if risk_score_norm == 0.0 and detection_rate_norm < 0.01:
            return 'allowlist'

        return 'suspicious'
    
    def vote_pulsedive(self, row):
        """Vote from Pulsedive source"""
        # Mapeamento 1-6 normalizado
        risk = row.get('risk_recommended_pulsedive', 0)
        
        # Medium(4), High(5), Critical(6) -> >= 0.6 (aprox 0.55 para margem)
        if risk >= 0.55:  
            return 'denylist'
        # None(1) -> 0.0
        elif risk <= 0.1:  
            return 'allowlist'
        else:
            return 'suspicious'
    
    def calculate_source_performance(self, df_norm, ground_truth):
        self.logger.info("Analyzing individual source performance...")
        sources = {
            'abuseipdb': self.vote_abuseipdb,
            'virustotal': self.vote_virustotal,
            'apivoid': self.vote_apivoid,
            'pulsedive': self.vote_pulsedive
        }
        performance_scores = {}
        for source_name, vote_func in sources.items():
            predictions = [vote_func(row) for _, row in df_norm.iterrows()]
            accuracy = accuracy_score(ground_truth, predictions)
            performance_scores[source_name] = accuracy
            self.logger.info(f"{source_name:15s}: {accuracy:.3f}")
        return performance_scores
    
    def calculate_correlation_weights(self, df_norm, ground_truth):
        self.logger.info("Calculating correlation weights...")
        class_mapping = {'allowlist': 0, 'suspicious': 1, 'denylist': 2}
        y_encoded = [class_mapping[gt] for gt in ground_truth]
        
        correlations = {}
        correlations['abuseipdb'] = abs(np.corrcoef(df_norm['abuseipdb_confidence_score'], y_encoded)[0,1])
        
        vt_combined = (df_norm['virustotal_malicious'] + 
                      (1 - df_norm['virustotal_harmless']) + 
                      (1 - df_norm['virustotal_reputation'])) / 3
        correlations['virustotal'] = abs(np.corrcoef(vt_combined, y_encoded)[0,1])
        
        api_combined = (df_norm['apivoid_risk_score'] + df_norm['apivoid_blacklists_detection_rate']) / 2
        correlations['apivoid'] = abs(np.corrcoef(api_combined, y_encoded)[0,1])
        
        correlations['pulsedive'] = abs(np.corrcoef(df_norm['risk_recommended_pulsedive'], y_encoded)[0,1])
        
        self.logger.info("Correlations calculated:")
        for source, corr in correlations.items():
            self.logger.info(f"  {source:15s}: {corr:.3f}")
        return correlations
    
    def calculate_consensus_weights(self, df_norm, ground_truth):
        self.logger.info("Calculating consensus weights...")
        sources = {
            'abuseipdb': self.vote_abuseipdb,
            'virustotal': self.vote_virustotal,
            'apivoid': self.vote_apivoid,
            'pulsedive': self.vote_pulsedive
        }
        
        all_votes = {name: [func(row) for _, row in df_norm.iterrows()] for name, func in sources.items()}
        consensus_scores = {}
        
        for source_name in sources.keys():
            agreements = 0
            total = len(ground_truth)
            for i in range(total):
                source_vote = all_votes[source_name][i]
                true_class = ground_truth[i]
                for other in sources.keys():
                    if other != source_name and source_vote == true_class and all_votes[other][i] == true_class:
                        agreements += 1

            consensus_scores[source_name] = agreements / (total * 3) if total > 0 else 0
            self.logger.info(f"{source_name:15s}: {consensus_scores[source_name]:.3f}")
            
        return consensus_scores
    
    def determine_optimal_weights(self, df_norm, ground_truth):
        self.logger.info("Determining optimal weights...")
        perf = self.calculate_source_performance(df_norm, ground_truth)
        corr = self.calculate_correlation_weights(df_norm, ground_truth)
        cons = self.calculate_consensus_weights(df_norm, ground_truth)
        
        sources = ['abuseipdb', 'virustotal', 'apivoid', 'pulsedive']
        combined = {}
        
        self.logger.info("DETAILED WEIGHT CALCULATION:")
        self.logger.info("=" * 60)
        
        for s in sources:
            score = (perf[s] * 0.5) + (corr[s] * 0.3) + (cons[s] * 0.2)
            combined[s] = score
            self.logger.info(f"{s:15s}: Perf={perf[s]:.3f}, Corr={corr[s]:.3f}, Cons={cons[s]:.3f} -> Total={score:.3f}")
            
        total = sum(combined.values())
        self.optimal_weights = {k: v/total for k, v in combined.items()}
        
        self.logger.info("=" * 60)
        self.logger.info("FINAL NORMALIZED WEIGHTS:")
        for k, v in self.optimal_weights.items():
            self.logger.info(f"  {k:15s}: {v:.3f}")
            
        return self.optimal_weights
    
    def create_ground_truth(self, df_processed):
        self.logger.info("Creating ground truth based on updated rules...")
        ground_truth = []
        
        counts = {'deny': 0, 'allow': 0, 'suspicious': 0}
        
        for _, row in df_processed.iterrows():
            abuse_conf = row.get('abuseipdb_confidence_score', 0)
            abuse_rep = row.get('abuseipdb_total_reports', 0)
            abuse_users = row.get('abuseipdb_num_distinct_users', 0)
            
            vt_mal = row.get('virustotal_malicious', 0)
            vt_rep = row.get('virustotal_reputation', 0)
            vt_harm = row.get('virustotal_harmless', 0)
            vt_undet = row.get('virustotal_undetected', 0)
            
            pulse_risk = row.get('risk_recommended_pulsedive', 2)
            
            api_risk = row.get('apivoid_risk_score', 0)
            api_rate = row.get('apivoid_blacklists_detection_rate', 0)
            
            label = 'suspicious'
            
            # 1. DENYLIST RULES
            deny_abuse = (abuse_conf > 60) or (abuse_rep > 40 and abuse_users > 30)
            deny_vt = (vt_mal > 1) or (vt_rep < -7)
            deny_pulse = (pulse_risk >= 4)
            deny_api = (api_risk > 60) or (api_rate > 0.02)
            
            if deny_abuse or deny_vt or deny_pulse or deny_api:
                label = 'denylist'
                counts['deny'] += 1
            
            # 2. ALLOWLIST RULES (Se não for Deny)
            else:
                allow_abuse = (abuse_conf == 0) and (abuse_rep < 20 and abuse_users < 10)
                # VT Allow: Exige Malicious 0, Rep > 0 e validação forte (Harmless/Undet > 40)
                allow_vt = (vt_mal == 0) and (vt_rep > 0) and (vt_harm > 40) and (vt_undet > 40)
                allow_pulse = (pulse_risk == 1)
                allow_api = (api_risk == 0) and (api_rate < 0.01)
                
                # Consenso: AbuseIPDB sozinho ou 2+ outras fontes
                clean_sources = sum([allow_abuse, allow_vt, allow_pulse, allow_api])
                
                if allow_abuse or clean_sources >= 2:
                    label = 'allowlist'
                    counts['allow'] += 1
                else:
                    counts['suspicious'] += 1
            
            ground_truth.append(label)
            
        self.logger.info(f"Ground Truth Distribution: {counts}")
        return ground_truth
    
    def classify_with_weighted_voting(self, df_norm, weights):
        self.logger.info("Classifying with weighted voting...")
        sources = {
            'abuseipdb': self.vote_abuseipdb,
            'virustotal': self.vote_virustotal,
            'apivoid': self.vote_apivoid,
            'pulsedive': self.vote_pulsedive
        }
        
        predictions = []
        confidences = []
        
        for _, row in df_norm.iterrows():
            scores = {'allowlist': 0, 'suspicious': 0, 'denylist': 0}
            
            for source, func in sources.items():
                vote = func(row)
                scores[vote] += weights[source]
            
            final_class = max(scores, key=scores.get)
            predictions.append(final_class)
            confidences.append(scores[final_class])
            
        return predictions, confidences