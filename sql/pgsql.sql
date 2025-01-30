-- SQL para a criação das tabelas do banco local -- 
CREATE TABLE network_traffic (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITHOUT TIME ZONE,
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    protocol_name VARCHAR(50),
    src_service VARCHAR(50),
    dst_service VARCHAR(50),
    src_country_code VARCHAR(3),
    src_city VARCHAR(255),
    src_latitude FLOAT,
    src_longitude FLOAT,
    dst_country_code VARCHAR(3),
    dst_city VARCHAR(255),
    dst_latitude FLOAT,
    dst_longitude FLOAT,
    src_port INT,
    dst_port INT,
    connection_time FLOAT,
    CONSTRAINT unique_traffic UNIQUE (timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_latitude, src_longitude, dst_country_code, dst_city, dst_latitude, dst_longitude, src_port, dst_port, connection_time) -- Restringe todos os campos a serem iguais
);

CREATE TABLE wl_address_local (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    country_code VARCHAR(3),
    city VARCHAR(255),
    abuse_confidence_score INT,
    total_reports FLOAT,
    num_distinct_users FLOAT,
    virustotal_reputation INT,
    harmless_virustotal INT,
    malicious_virustotal INT,
    suspicious_virustotal INT,
    undetected_virustotal INT,
    ipvoid_detection_count INT,
    risk_recommended_pulsedive VARCHAR(45),
    last_reported_at TIMESTAMP WITHOUT TIME ZONE,
    src_longitude FLOAT,
    src_latitude FLOAT,
    timestamp_added TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE bl_address_local (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    country_code VARCHAR(3),
    city VARCHAR(255),
    abuse_confidence_score INT,
    total_reports FLOAT,
    num_distinct_users FLOAT,
    virustotal_reputation INT,
    harmless_virustotal INT,
    malicious_virustotal INT,
    suspicious_virustotal INT,
    undetected_virustotal INT,
    ipvoid_detection_count INT,
    risk_recommended_pulsedive VARCHAR(45),
    last_reported_at TIMESTAMP WITHOUT TIME ZONE,
    src_longitude FLOAT,
    src_latitude FLOAT,
    timestamp_added TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
