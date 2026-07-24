//! Password acquisition for the CLI.
//!
//! A password is never accepted as a command-line argument: argv is visible to
//! every user on the machine (`ps`, /proc, Windows WMI) and lands in shell
//! history. The supported sources are, in order of precedence: stdin, a file,
//! a named environment variable, the `CRYPTERA_PASSWORD` variable, and finally
//! an interactive no-echo prompt.

use std::io::{BufRead, IsTerminal};
use std::path::Path;

use secrecy::Secret;

use crate::error::{CliError, ERR_PASSWORD_REQUIRED};

/// Environment variable consulted when no explicit source is given.
pub const DEFAULT_PASSWORD_ENV: &str = "CRYPTERA_PASSWORD";

#[derive(Debug, Clone, Default)]
pub struct PasswordSource<'a> {
    pub env: Option<&'a str>,
    pub file: Option<&'a Path>,
    pub stdin: bool,
}

/// Resolve the password. `confirm` asks for it twice, but only when the
/// interactive prompt is actually used (there is nothing to confirm when the
/// value comes from a script).
pub fn resolve(src: &PasswordSource<'_>, confirm: bool) -> Result<Secret<String>, CliError> {
    let raw = if src.stdin {
        read_first_line(&mut std::io::stdin().lock())?
    } else if let Some(path) = src.file {
        let file = std::fs::File::open(path).map_err(|e| {
            CliError::new(
                ERR_PASSWORD_REQUIRED,
                format!("cannot read password file {}: {e}", path.display()),
            )
        })?;
        read_first_line(&mut std::io::BufReader::new(file))?
    } else if let Some(var) = src.env {
        std::env::var(var).map_err(|_| {
            CliError::new(
                ERR_PASSWORD_REQUIRED,
                format!("environment variable {var} is not set"),
            )
        })?
    } else if let Ok(value) = std::env::var(DEFAULT_PASSWORD_ENV) {
        value
    } else if std::io::stdin().is_terminal() {
        return prompt(confirm);
    } else {
        return Err(CliError::new(
            ERR_PASSWORD_REQUIRED,
            format!(
                "no password source: use --password-stdin, --password-file, \
                 --password-env, or set {DEFAULT_PASSWORD_ENV}"
            ),
        ));
    };

    check_not_blank(&raw)?;
    Ok(Secret::new(raw))
}

fn prompt(confirm: bool) -> Result<Secret<String>, CliError> {
    let first = rpassword::prompt_password("Password: ")
        .map_err(|e| CliError::new(ERR_PASSWORD_REQUIRED, e.to_string()))?;
    check_not_blank(&first)?;
    if confirm {
        let again = rpassword::prompt_password("Confirm password: ")
            .map_err(|e| CliError::new(ERR_PASSWORD_REQUIRED, e.to_string()))?;
        if again != first {
            return Err(CliError::new(
                ERR_PASSWORD_REQUIRED,
                "passwords do not match",
            ));
        }
    }
    Ok(Secret::new(first))
}

/// Read one line, dropping only the line terminator: any other whitespace is
/// part of the password.
fn read_first_line(reader: &mut impl BufRead) -> Result<String, CliError> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| CliError::new(ERR_PASSWORD_REQUIRED, e.to_string()))?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Same rule as the GUI: a blank password is refused before any key derivation.
fn check_not_blank(value: &str) -> Result<(), CliError> {
    if value.trim().is_empty() {
        return Err(CliError::new(ERR_PASSWORD_REQUIRED, "password is empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn line_terminators_are_stripped_but_inner_spaces_kept() {
        let mut input = &b"  pass word  \r\nsecond line\n"[..];
        assert_eq!(read_first_line(&mut input).unwrap(), "  pass word  ");
    }

    #[test]
    fn missing_terminator_is_fine() {
        let mut input = &b"lastline"[..];
        assert_eq!(read_first_line(&mut input).unwrap(), "lastline");
    }

    #[test]
    fn blank_passwords_are_refused() {
        assert!(check_not_blank("   ").is_err());
        assert!(check_not_blank("\t").is_err());
        assert!(check_not_blank("x").is_ok());
    }

    #[test]
    fn file_source_reads_first_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.txt");
        std::fs::write(&path, "hunter2\nignored\n").unwrap();
        let src = PasswordSource {
            file: Some(&path),
            ..Default::default()
        };
        let pw = resolve(&src, false).unwrap();
        assert_eq!(pw.expose_secret(), "hunter2");
    }

    #[test]
    fn missing_file_reports_password_required() {
        let src = PasswordSource {
            file: Some(Path::new("/definitely/not/here")),
            ..Default::default()
        };
        let err = resolve(&src, false).unwrap_err();
        assert_eq!(err.code, ERR_PASSWORD_REQUIRED);
    }
}
