use std::str::FromStr;

#[derive(Debug, Clone, Default)]
pub struct ValidatorIndexes(Vec<u64>);

impl ValidatorIndexes {
    pub fn contains(&self, index: u64) -> bool {
        self.0.contains(&index)
    }
}

impl FromStr for ValidatorIndexes {
    type Err = eyre::Report;

    /// Parse an array of validator indexes. Accepted values:
    /// - a comma-separated list of indexes (e.g. "1,2,3,4")
    /// - a contiguous range of indexes (e.g. "1..4")
    /// - a mix of the above (e.g. "1,2..4,6..8")
    ///
    /// TODO: add parsing from a directory path, using the format of
    /// validator definitions
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let mut vec = Vec::new();

        for comma_separated_part in s.split(',') {
            if comma_separated_part.contains("..") {
                let mut parts = comma_separated_part.split("..");

                let start = parts.next().ok_or_else(|| eyre::eyre!("Invalid range"))?;
                let start = start.parse::<u64>()?;

                let end = parts.next().ok_or_else(|| eyre::eyre!("Invalid range"))?;
                let end = end.parse::<u64>()?;

                vec.extend(start..=end);
            } else {
                let index = comma_separated_part.parse::<u64>()?;
                vec.push(index);
            }
        }

        Ok(Self(vec))
    }
}

impl From<Vec<u64>> for ValidatorIndexes {
    fn from(vec: Vec<u64>) -> Self {
        Self(vec)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_validator_indexes() {
        use super::ValidatorIndexes;
        use std::str::FromStr;

        let indexes = ValidatorIndexes::from_str("1,2,3,4").unwrap();
        assert_eq!(indexes.0, vec![1, 2, 3, 4]);

        let indexes = ValidatorIndexes::from_str("1..4").unwrap();
        assert_eq!(indexes.0, vec![1, 2, 3, 4]);

        let indexes = ValidatorIndexes::from_str("1..4,6..8").unwrap();
        assert_eq!(indexes.0, vec![1, 2, 3, 4, 6, 7, 8]);

        let indexes = ValidatorIndexes::from_str("1,2..4,6..8").unwrap();
        assert_eq!(indexes.0, vec![1, 2, 3, 4, 6, 7, 8]);
    }
}
