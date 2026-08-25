CREATE INDEX cryptoscan_system_name IF NOT EXISTS FOR (s:System) ON (s.name);
CREATE INDEX cryptoscan_asset_algo IF NOT EXISTS FOR (a:CryptoAsset) ON (a.algorithm);
CREATE INDEX cryptoscan_process_name IF NOT EXISTS FOR (p:BusinessProcess) ON (p.name);
