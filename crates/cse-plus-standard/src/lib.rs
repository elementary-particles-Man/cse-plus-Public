//! Public CSE+ metadata and helpers.

use serde::{Deserialize, Serialize};

pub const PUBLIC_LINE_NAME: &str = "cse-plus-standard";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardLineInfo {
    pub name: String,
    pub public: bool,
}

pub fn standard_line_info() -> StandardLineInfo {
    StandardLineInfo {
        name: PUBLIC_LINE_NAME.to_string(),
        public: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_line_info_is_public() {
        let info = standard_line_info();
        assert_eq!(info.name, PUBLIC_LINE_NAME);
        assert!(info.public);
    }
}
