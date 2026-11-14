//! Operator confirmation prompts for destructive maintenance actions.

use dialoguer::Confirm;
use crate::core::error::{CfmsError, Result};

/// Require interactive confirmation unless `yes` (`--yes`) was supplied.
pub fn confirm_or_abort(prompt: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    let confirmed = Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?;

    if confirmed {
        Ok(())
    } else {
        Err(CfmsError::OperationAborted)
    }
}
