//! CLI error type and the exit codes scripts branch on.

use cryptera_ops::OpError;

pub const ERR_PASSWORD_REQUIRED: &str = "PASSWORD_REQUIRED";
pub const ERR_INPUT_REQUIRED: &str = "INPUT_REQUIRED";
pub const ERR_OUTPUT_EXISTS: &str = "OUTPUT_EXISTS";
pub const ERR_IO: &str = "IO_ERROR";

/// Exit codes. 2 is left to clap for usage errors.
pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_BAD_PASSWORD: i32 = 3;
pub const EXIT_CORRUPT: i32 = 4;
pub const EXIT_OUTPUT_EXISTS: i32 = 5;
pub const EXIT_CANCELLED: i32 = 6;

#[derive(Debug, Clone)]
pub struct CliError {
    pub code: String,
    pub message: String,
}

impl CliError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    /// Stable, scriptable exit status derived from the error code.
    pub fn exit_code(&self) -> i32 {
        match self.code.as_str() {
            "PASSWORD_INVALID" | "HEADER_AUTH_FAILED" => EXIT_BAD_PASSWORD,
            "CORRUPT_BEYOND_FEC" | "HEADER_INVALID" | "TRUNCATED" | "PARAMS_OUT_OF_LIMITS" => {
                EXIT_CORRUPT
            }
            ERR_OUTPUT_EXISTS => EXIT_OUTPUT_EXISTS,
            "CANCELLED" => EXIT_CANCELLED,
            _ => EXIT_ERROR,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<OpError> for CliError {
    fn from(e: OpError) -> Self {
        Self {
            code: e.code,
            message: e.message,
        }
    }
}

impl From<crypto_core_rs::CoreError> for CliError {
    fn from(e: crypto_core_rs::CoreError) -> Self {
        Self {
            code: e.code.to_string(),
            message: e.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(
            CliError::new("PASSWORD_INVALID", "").exit_code(),
            EXIT_BAD_PASSWORD
        );
        assert_eq!(
            CliError::new("HEADER_AUTH_FAILED", "").exit_code(),
            EXIT_BAD_PASSWORD
        );
        assert_eq!(
            CliError::new("CORRUPT_BEYOND_FEC", "").exit_code(),
            EXIT_CORRUPT
        );
        assert_eq!(
            CliError::new(ERR_OUTPUT_EXISTS, "").exit_code(),
            EXIT_OUTPUT_EXISTS
        );
        assert_eq!(CliError::new("CANCELLED", "").exit_code(), EXIT_CANCELLED);
        assert_eq!(CliError::new("IO_ERROR", "").exit_code(), EXIT_ERROR);
    }

    #[test]
    fn core_and_op_errors_keep_their_code() {
        let core = crypto_core_rs::CoreError::new("PASSWORD_INVALID", "nope");
        assert_eq!(CliError::from(core).exit_code(), EXIT_BAD_PASSWORD);
        let op = OpError::new(cryptera_ops::ERR_TAR, "boom");
        assert_eq!(CliError::from(op).code, "TAR_ERROR");
    }
}
