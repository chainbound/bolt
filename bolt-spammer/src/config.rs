use eyre::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub execution_api: String,
    pub beacon_api: String,
    pub bolt: ProtocolConfig,
    pub titan: ProtocolConfig,
}

impl Config {
    pub fn from_toml(path: &str) -> Result<Config> {
        let config = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&config)?;
        Ok(config)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub endpoint: String,
    pub validator_range: ValidatorRange,
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorRange {
    pub start: usize,
    pub end: usize,
}

impl ValidatorRange {
    pub fn is_in_range(&self, index: usize) -> bool {
        index >= self.start && index <= self.end
    }
}
