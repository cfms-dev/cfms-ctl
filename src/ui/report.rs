//! Dual-mode output renderer (`Human` vs `Json`) and table formatting helpers.

use clap::ValueEnum;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use console::style;
use serde::Serialize;
use crate::core::error::CfmsError;

/// Output mode selected via `--output`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Rich terminal tables and styled panels for interactive operators.
    #[default]
    Human,
    /// Structured JSON document on stdout for scripts and automation.
    Json,
}

/// Trait implemented by every operation result in `src/ops/`.
pub trait CommandReport: Serialize {
    /// Render this report to the terminal in human-readable form.
    fn render_human(&self, ui: &UiConsole);
}

/// Console wrapper managing human vs JSON output.
#[derive(Debug, Clone)]
pub struct UiConsole {
    format: OutputFormat,
}

impl UiConsole {
    #[must_use]
    pub const fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    #[must_use]
    pub const fn format(&self) -> OutputFormat {
        self.format
    }

    /// Render a successful operation report in the configured output format.
    pub fn render<R: CommandReport>(&self, report: &R) {
        match self.format {
            OutputFormat::Human => report.render_human(self),
            OutputFormat::Json => {
                let envelope = serde_json::json!({
                    "status": "ok",
                    "data": report,
                });
                if let Ok(json) = serde_json::to_string_pretty(&envelope) {
                    println!("{json}");
                }
            }
        }
    }

    /// Render an error to stderr (in `Human` mode) or stdout JSON envelope (in `Json` mode).
    pub fn render_error(&self, err: &CfmsError) {
        match self.format {
            OutputFormat::Human => {
                eprintln!(
                    "\n{} {}\n  {} {}\n",
                    style("✖ Maintenance command failed").red().bold(),
                    style(format!("[{:?}]", err.code())).dim(),
                    style("→").red(),
                    err
                );
            }
            OutputFormat::Json => {
                let envelope = serde_json::json!({
                    "status": "error",
                    "code": err.code(),
                    "message": err.to_string(),
                });
                if let Ok(json) = serde_json::to_string_pretty(&envelope) {
                    println!("{json}");
                }
            }
        }
    }

    /// Print a styled section title in `Human` mode.
    pub fn print_section(&self, title: &str) {
        if self.format == OutputFormat::Human {
            println!("\n{}", style(format!("=== {title} ===")).cyan().bold());
        }
    }

    /// Print a success banner in `Human` mode.
    pub fn print_success(&self, message: &str) {
        if self.format == OutputFormat::Human {
            println!("{} {}", style("✔").green().bold(), message);
        }
    }

    /// Print a warning banner in `Human` mode.
    pub fn print_warning(&self, message: &str) {
        if self.format == OutputFormat::Human {
            eprintln!("{} {}", style("⚠ Warning:").yellow().bold(), message);
        }
    }

    /// Print an error line in `Human` mode.
    pub fn print_error(&self, message: &str) {
        if self.format == OutputFormat::Human {
            eprintln!("{} {}", style("✖").red().bold(), message);
        }
    }
}

/// Helper builder for two-column key-value summary tables in `Human` mode.
pub struct KeyValueTable {
    title: String,
    rows: Vec<(String, String)>,
}

impl KeyValueTable {
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.rows.push((key.into(), value.into()));
        self
    }

    pub fn print(&self) {
        println!("\n{}", style(&self.title).bold().underlined());
        let mut table = Table::new();
        table
            .load_style(UTF8_FULL.with_rounded_corners())
            .set_content_arrangement(ContentArrangement::Dynamic);
        for (k, v) in &self.rows {
            table.add_row(vec![
                Cell::new(k).fg(Color::Cyan),
                Cell::new(v).fg(Color::Green),
            ]);
        }
        println!("{table}");
    }
}

/// Create a pre-styled multi-column table with headers.
#[must_use]
pub fn styled_table(headers: &[&str]) -> Table {
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL.with_rounded_corners())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(
            headers
                .iter()
                .map(|h| Cell::new(*h).fg(Color::Cyan))
                .collect::<Vec<_>>(),
        );
    table
}
