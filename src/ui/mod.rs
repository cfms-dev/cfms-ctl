//! Terminal presentation layer supporting both human-friendly tables and
//! machine-readable JSON output (`--output human|json`).

pub mod prompt;
pub mod report;

pub use prompt::confirm_or_abort;
pub use report::{CommandReport, KeyValueTable, OutputFormat, UiConsole, styled_table};
