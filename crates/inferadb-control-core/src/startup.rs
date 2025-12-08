//! Startup display utilities for InferaDB services
//!
//! Provides consistent, structured startup output across all InferaDB binaries.
//! Includes TRON-style ASCII art banner and configuration summary formatting.

use std::io::IsTerminal;

use terminal_size::{Width, terminal_size};
use unicode_width::UnicodeWidthStr;

/// ANSI color codes for TRON aesthetic
mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const CYAN: &str = "\x1b[36m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
}

/// ASCII art for "INFERADB" in FIGlet-style block letters
const ASCII_ART: &[&str] = &[
    "██╗███╗   ██╗███████╗███████╗██████╗  █████╗ ██████╗ ██████╗ ",
    "██║████╗  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗",
    "██║██╔██╗ ██║█████╗  █████╗  ██████╔╝███████║██║  ██║██████╔╝",
    "██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══██╗██╔══██║██║  ██║██╔══██╗",
    "██║██║ ╚████║██║     ███████╗██║  ██║██║  ██║██████╔╝██████╔╝",
    "╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ",
];

/// Width of the full ASCII art (in characters)
const ASCII_ART_WIDTH: usize = 61;

/// Minimum terminal width for full ASCII art display
const MIN_WIDTH_FOR_FULL_ART: usize = 80;

/// Minimum terminal width for table display
const MIN_WIDTH_FOR_TABLE: usize = 50;

/// Service information for the startup banner
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service name (e.g., "InferaDB")
    pub name: &'static str,
    /// Service subtext (e.g., "Management API Service")
    pub subtext: &'static str,
    /// Version string
    pub version: &'static str,
    /// Environment (development, staging, production)
    pub environment: String,
}

/// Style variant for configuration entry display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigEntryStyle {
    /// Normal green display (default)
    #[default]
    Normal,
    /// Warning/unassigned yellow display
    Warning,
    /// Sensitive value (masked)
    Sensitive,
    /// Separator line (renders as horizontal divider in table)
    Separator,
}

/// A single configuration entry for display
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    /// Category/group name (e.g., "General", "Server")
    pub category: &'static str,
    /// Human-friendly display name (e.g., "Environment")
    pub display_name: String,
    /// Configuration value (already formatted as string)
    pub value: String,
    /// Whether this is a sensitive value that should be masked
    pub sensitive: bool,
    /// Display style for this entry
    pub style: ConfigEntryStyle,
}

impl ConfigEntry {
    /// Create a new configuration entry with a display name
    pub fn new(
        category: &'static str,
        display_name: impl Into<String>,
        value: impl ToString,
    ) -> Self {
        Self {
            category,
            display_name: display_name.into(),
            value: value.to_string(),
            sensitive: false,
            style: ConfigEntryStyle::Normal,
        }
    }

    /// Create a sensitive configuration entry (value will be masked)
    pub fn sensitive(
        category: &'static str,
        display_name: impl Into<String>,
        value: impl ToString,
    ) -> Self {
        Self {
            category,
            display_name: display_name.into(),
            value: value.to_string(),
            sensitive: true,
            style: ConfigEntryStyle::Sensitive,
        }
    }

    /// Create a warning-styled configuration entry (displayed in yellow)
    pub fn warning(
        category: &'static str,
        display_name: impl Into<String>,
        value: impl ToString,
    ) -> Self {
        Self {
            category,
            display_name: display_name.into(),
            value: value.to_string(),
            sensitive: false,
            style: ConfigEntryStyle::Warning,
        }
    }

    /// Mark an entry as sensitive
    pub fn as_sensitive(mut self) -> Self {
        self.sensitive = true;
        self.style = ConfigEntryStyle::Sensitive;
        self
    }

    /// Mark an entry as warning style
    pub fn as_warning(mut self) -> Self {
        self.style = ConfigEntryStyle::Warning;
        self
    }

    /// Create a separator entry (renders as horizontal divider in table)
    ///
    /// Separators visually divide groups of entries within a single category.
    pub fn separator(category: &'static str) -> Self {
        Self {
            category,
            display_name: String::new(),
            value: String::new(),
            sensitive: false,
            style: ConfigEntryStyle::Separator,
        }
    }
}

/// Builder for creating a structured startup display
pub struct StartupDisplay {
    service: ServiceInfo,
    entries: Vec<ConfigEntry>,
    use_ansi: bool,
}

impl StartupDisplay {
    /// Create a new startup display builder
    pub fn new(service: ServiceInfo) -> Self {
        Self { service, entries: Vec::new(), use_ansi: std::io::stdout().is_terminal() }
    }

    /// Set whether to use ANSI colors
    pub fn with_ansi(mut self, use_ansi: bool) -> Self {
        self.use_ansi = use_ansi;
        self
    }

    /// Add a configuration entry
    pub fn entry(mut self, entry: ConfigEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Add multiple configuration entries
    pub fn entries(mut self, entries: impl IntoIterator<Item = ConfigEntry>) -> Self {
        self.entries.extend(entries);
        self
    }

    /// Display the startup banner and configuration summary
    pub fn display(&self) {
        self.print_banner();
        self.print_config_summary();
    }

    /// Get terminal width, defaulting to 80 if detection fails
    pub fn get_terminal_width() -> usize {
        terminal_size().map(|(Width(w), _)| w as usize).unwrap_or(80)
    }

    fn print_banner(&self) {
        let width = Self::get_terminal_width();
        let use_full_art = width >= MIN_WIDTH_FOR_FULL_ART;

        if use_full_art {
            self.print_full_banner(width);
        } else {
            self.print_compact_banner(width);
        }
    }

    fn print_full_banner(&self, terminal_width: usize) {
        let (reset, bold, dim, bright_cyan) = if self.use_ansi {
            (colors::RESET, colors::BOLD, colors::DIM, colors::BRIGHT_CYAN)
        } else {
            ("", "", "", "")
        };

        // Calculate left padding to center the ASCII art
        let art_left_pad = terminal_width.saturating_sub(ASCII_ART_WIDTH) / 2;
        let art_indent = " ".repeat(art_left_pad);

        println!();

        // ASCII art lines (centered, no border)
        for line in ASCII_ART {
            println!("{art_indent}{bold}{bright_cyan}{line}{reset}");
        }

        // Empty line
        println!();

        // Subtext (centered)
        let subtext = self.service.subtext;
        let subtext_left_pad = terminal_width.saturating_sub(subtext.len()) / 2;
        println!("{left_pad}{dim}{subtext}{reset}", left_pad = " ".repeat(subtext_left_pad));

        // Version (centered)
        let version_str = format!("v{}", self.service.version);
        let version_left_pad = terminal_width.saturating_sub(version_str.len()) / 2;
        println!("{left_pad}{dim}{version_str}{reset}", left_pad = " ".repeat(version_left_pad));

        println!();
    }

    fn print_compact_banner(&self, terminal_width: usize) {
        let (reset, bold, dim, bright_cyan) = if self.use_ansi {
            (colors::RESET, colors::BOLD, colors::DIM, colors::BRIGHT_CYAN)
        } else {
            ("", "", "", "")
        };

        println!();

        // Title line with decorative elements (centered, no border)
        let title = "▀▀▀ INFERADB ▀▀▀";
        let title_left_pad = terminal_width.saturating_sub(title.len()) / 2;
        println!(
            "{left_pad}{bold}{bright_cyan}{title}{reset}",
            left_pad = " ".repeat(title_left_pad)
        );

        // Subtext (centered)
        let subtext = self.service.subtext;
        let subtext_left_pad = terminal_width.saturating_sub(subtext.len()) / 2;
        println!("{left_pad}{dim}{subtext}{reset}", left_pad = " ".repeat(subtext_left_pad));

        // Version (centered)
        let version_str = format!("v{}", self.service.version);
        let version_left_pad = terminal_width.saturating_sub(version_str.len()) / 2;
        println!("{left_pad}{dim}{version_str}{reset}", left_pad = " ".repeat(version_left_pad));

        println!();
    }

    fn print_config_summary(&self) {
        if self.entries.is_empty() {
            return;
        }

        let terminal_width = Self::get_terminal_width();

        // Group entries by category
        let mut categories: Vec<(&str, Vec<&ConfigEntry>)> = Vec::new();
        for entry in &self.entries {
            if let Some((_, entries)) =
                categories.iter_mut().find(|(cat, _)| *cat == entry.category)
            {
                entries.push(entry);
            } else {
                categories.push((entry.category, vec![entry]));
            }
        }

        // Use table format if terminal is wide enough
        if terminal_width >= MIN_WIDTH_FOR_TABLE {
            self.print_config_tables(&categories, terminal_width);
        } else {
            self.print_config_simple(&categories);
        }
    }

    fn print_config_tables(&self, categories: &[(&str, Vec<&ConfigEntry>)], terminal_width: usize) {
        let (reset, dim, cyan, green, yellow) = if self.use_ansi {
            (colors::RESET, colors::DIM, colors::CYAN, colors::GREEN, colors::YELLOW)
        } else {
            ("", "", "", "", "")
        };

        for (category, entries) in categories {
            // Print category header
            println!("{dim}# {category}{reset}");

            // Calculate column widths for this category
            let max_property_len = entries.iter().map(|e| e.display_name.len()).max().unwrap_or(0);

            // Table should fill terminal width
            // Layout: ║ Property ║ Value ║
            // Characters: 3 borders (3) + 4 spaces padding (4) = 7 fixed chars
            let table_width = terminal_width;
            let property_col_width = max_property_len;

            // Value column gets remaining space after property column and fixed chars
            let value_col_width = table_width
                .saturating_sub(3) // 3 border characters (║ ║ ║)
                .saturating_sub(4) // 4 padding spaces
                .saturating_sub(property_col_width)
                .max(10); // Minimum value column width

            // Draw top border
            println!(
                "{cyan}╔{prop_border}╦{val_border}╗{reset}",
                prop_border = "═".repeat(property_col_width + 2),
                val_border = "═".repeat(value_col_width + 2)
            );

            // Draw data rows
            for entry in entries {
                // Handle separator entries
                if entry.style == ConfigEntryStyle::Separator {
                    println!(
                        "{cyan}╠{prop_border}╬{val_border}╣{reset}",
                        prop_border = "═".repeat(property_col_width + 2),
                        val_border = "═".repeat(value_col_width + 2)
                    );
                    continue;
                }

                let (display_value, value_display_len) = match entry.style {
                    ConfigEntryStyle::Sensitive => (format!("{yellow}********{reset}"), 8),
                    ConfigEntryStyle::Warning => {
                        let val = &entry.value;
                        let display_width = val.width();
                        if display_width > value_col_width {
                            // Truncate by character count, accounting for unicode width
                            let mut truncated = String::new();
                            let mut width = 0;
                            for c in val.chars() {
                                let char_width =
                                    unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
                                if width + char_width > value_col_width.saturating_sub(3) {
                                    break;
                                }
                                truncated.push(c);
                                width += char_width;
                            }
                            (format!("{yellow}{}...{reset}", truncated), value_col_width)
                        } else {
                            (format!("{yellow}{}{reset}", val), display_width)
                        }
                    },
                    ConfigEntryStyle::Normal => {
                        let val = &entry.value;
                        let display_width = val.width();
                        if display_width > value_col_width {
                            // Truncate by character count, accounting for unicode width
                            let mut truncated = String::new();
                            let mut width = 0;
                            for c in val.chars() {
                                let char_width =
                                    unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
                                if width + char_width > value_col_width.saturating_sub(3) {
                                    break;
                                }
                                truncated.push(c);
                                width += char_width;
                            }
                            (format!("{green}{}...{reset}", truncated), value_col_width)
                        } else {
                            (format!("{green}{}{reset}", val), display_width)
                        }
                    },
                    ConfigEntryStyle::Separator => unreachable!(), // Handled above
                };

                let value_padding = value_col_width.saturating_sub(value_display_len);

                println!(
                    "{cyan}║{reset} {prop:<prop_width$} {cyan}║{reset} {val}{padding} {cyan}║{reset}",
                    prop = entry.display_name,
                    prop_width = property_col_width,
                    val = display_value,
                    padding = " ".repeat(value_padding)
                );
            }

            // Draw bottom border
            println!(
                "{cyan}╚{prop_border}╩{val_border}╝{reset}",
                prop_border = "═".repeat(property_col_width + 2),
                val_border = "═".repeat(value_col_width + 2)
            );

            println!();
        }
    }

    fn print_config_simple(&self, categories: &[(&str, Vec<&ConfigEntry>)]) {
        let (reset, dim, green, yellow) = if self.use_ansi {
            (colors::RESET, colors::DIM, colors::GREEN, colors::YELLOW)
        } else {
            ("", "", "", "")
        };

        for (category, entries) in categories {
            println!("{dim}# {category}{reset}");
            for entry in entries {
                // Handle separator entries
                if entry.style == ConfigEntryStyle::Separator {
                    println!("{dim}  ────{reset}");
                    continue;
                }

                let display_value = match entry.style {
                    ConfigEntryStyle::Sensitive => format!("{yellow}********{reset}"),
                    ConfigEntryStyle::Warning => format!("{yellow}{}{reset}", entry.value),
                    ConfigEntryStyle::Normal => format!("{green}{}{reset}", entry.value),
                    ConfigEntryStyle::Separator => unreachable!(), // Handled above
                };
                println!("  {}: {}", entry.display_name, display_value);
            }
            println!();
        }
    }
}

/// Log a startup phase header
///
/// Use this to clearly delineate initialization phases in the logs.
pub fn log_phase(phase: &str) {
    tracing::info!("━━━ {} ━━━", phase);
}

/// Log a successful initialization step
pub fn log_initialized(component: &str) {
    tracing::info!("✓ {} initialized", component);
}

/// Log a skipped initialization step
pub fn log_skipped(component: &str, reason: &str) {
    tracing::info!("○ {} skipped: {}", component, reason);
}

/// Log that the service is ready to accept connections
pub fn log_ready(service_name: &str) {
    tracing::info!("✓ {} started successfully", service_name);
}

/// Extract a hint from a PEM-encoded private key for display purposes.
///
/// Returns a truncated version like "✓ MC4C...aYc/" showing the key is configured.
pub fn private_key_hint(pem: &str) -> String {
    // Extract the base64 content from the PEM
    let lines: Vec<&str> = pem.lines().collect();
    let base64_content: String =
        lines.iter().filter(|line| !line.starts_with("-----")).copied().collect();

    if base64_content.len() > 8 {
        let start = &base64_content[..4];
        let end = &base64_content[base64_content.len() - 4..];
        format!("✓ {}...{}", start, end)
    } else if !base64_content.is_empty() {
        format!("✓ {}", base64_content)
    } else {
        "✓ Configured".to_string()
    }
}

/// Display a generated keypair in a formatted box
///
/// Displays the PEM in a warning-styled box and provides instructions
/// for persisting the key.
pub fn print_generated_keypair(pem: &str, config_key: &str) {
    use std::io::IsTerminal;

    let use_ansi = std::io::stdout().is_terminal();
    let (reset, bold, dim, yellow) = if use_ansi {
        (colors::RESET, colors::BOLD, colors::DIM, colors::YELLOW)
    } else {
        ("", "", "", "")
    };

    let terminal_width = StartupDisplay::get_terminal_width();

    // Print empty line before table
    println!();

    // Parse PEM lines
    let pem_lines: Vec<&str> = pem.lines().collect();
    let max_pem_line_len = pem_lines.iter().map(|l| l.len()).max().unwrap_or(0);

    // Box should fill terminal width
    // Layout: ║ content ║ = 2 borders + 2 padding spaces = 4 fixed chars
    let content_width = terminal_width.saturating_sub(4);
    let content_width = content_width.max(max_pem_line_len);

    // Title
    let title = "Generated Ed25519 Keypair";
    let title_left_pad = content_width.saturating_sub(title.len()) / 2;
    let title_right_pad = content_width.saturating_sub(title_left_pad + title.len());

    // Draw top border
    println!("{yellow}╔{border}╗{reset}", border = "═".repeat(content_width + 2));

    // Draw title row
    println!(
        "{yellow}║{reset} {left_pad}{bold}{title}{reset}{right_pad} {yellow}║{reset}",
        left_pad = " ".repeat(title_left_pad),
        right_pad = " ".repeat(title_right_pad)
    );

    // Draw separator
    println!("{yellow}╠{border}╣{reset}", border = "═".repeat(content_width + 2));

    // Draw PEM lines
    for line in &pem_lines {
        let line_padding = content_width.saturating_sub(line.len());
        println!(
            "{yellow}║{reset} {dim}{line}{reset}{padding} {yellow}║{reset}",
            padding = " ".repeat(line_padding)
        );
    }

    // Draw bottom border
    println!("{yellow}╚{border}╝{reset}", border = "═".repeat(content_width + 2));

    // Log follow-up warnings
    tracing::warn!("○ To persist this across restarts, add this key to your configuration");
    tracing::warn!("  For more information, see https://inferadb.com/docs/?search={}", config_key);

    // Print empty line after table
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_entry_creation() {
        let entry = ConfigEntry::new("Server", "Port", 8080);
        assert_eq!(entry.category, "Server");
        assert_eq!(entry.display_name, "Port");
        assert_eq!(entry.value, "8080");
        assert!(!entry.sensitive);
    }

    #[test]
    fn test_sensitive_entry() {
        let entry = ConfigEntry::sensitive("Auth", "Secret Key", "my-secret");
        assert!(entry.sensitive);

        let entry2 = ConfigEntry::new("Auth", "API Key", "value").as_sensitive();
        assert!(entry2.sensitive);
    }

    #[test]
    fn test_startup_display_builder() {
        let service = ServiceInfo {
            name: "Test Service",
            subtext: "Test Subtext",
            version: "0.1.0",
            environment: "test".to_string(),
        };

        let display = StartupDisplay::new(service)
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "Host", "0.0.0.0"))
            .entry(ConfigEntry::new("Server", "Port", 8080));

        assert_eq!(display.entries.len(), 2);
        assert!(!display.use_ansi);
    }

    #[test]
    fn test_startup_display_entries_batch() {
        let service = ServiceInfo {
            name: "Test Service",
            subtext: "Test Subtext",
            version: "0.1.0",
            environment: "test".to_string(),
        };

        let entries = vec![
            ConfigEntry::new("Server", "Host", "0.0.0.0"),
            ConfigEntry::new("Server", "Port", 8080),
            ConfigEntry::new("Storage", "Backend", "memory"),
        ];

        let display = StartupDisplay::new(service).entries(entries);

        assert_eq!(display.entries.len(), 3);
    }

    #[test]
    fn test_ascii_art_dimensions() {
        // Verify all ASCII art lines have consistent width
        for line in ASCII_ART {
            assert_eq!(
                line.chars().count(),
                ASCII_ART_WIDTH,
                "ASCII art line has inconsistent width"
            );
        }
    }

    #[test]
    fn test_terminal_width_detection() {
        // This test verifies the function doesn't panic
        let width = StartupDisplay::get_terminal_width();
        assert!(width > 0);
    }
}
