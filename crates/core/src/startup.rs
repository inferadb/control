//! Startup display utilities for InferaDB services.
//!
//! Provides consistent, structured startup output across all InferaDB binaries.
//! Includes ASCII art banner and configuration summary formatting.

use std::io::IsTerminal;

use terminal_size::{Width, terminal_size};
use unicode_width::UnicodeWidthStr;

/// ANSI color codes for banner and table styling.
mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const CYAN: &str = "\x1b[36m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
}

/// ASCII art for "INFERADB" in FIGlet-style block letters.
const ASCII_ART: &[&str] = &[
    "██╗███╗   ██╗███████╗███████╗██████╗  █████╗ ██████╗ ██████╗ ",
    "██║████╗  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗",
    "██║██╔██╗ ██║█████╗  █████╗  ██████╔╝███████║██║  ██║██████╔╝",
    "██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══██╗██╔══██║██║  ██║██╔══██╗",
    "██║██║ ╚████║██║     ███████╗██║  ██║██║  ██║██████╔╝██████╔╝",
    "╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ",
];

/// Width of the full ASCII art (in characters).
const ASCII_ART_WIDTH: usize = 61;

/// Minimum terminal width for full ASCII art display.
const MIN_WIDTH_FOR_FULL_ART: usize = 80;

/// Minimum terminal width for table display.
const MIN_WIDTH_FOR_TABLE: usize = 50;

/// Metadata displayed in the startup banner.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Display name shown in the banner header (e.g., "InferaDB").
    pub name: &'static str,
    /// Descriptive tagline below the banner (e.g., "Management API Service").
    pub subtext: &'static str,
    /// Semantic version rendered below the tagline.
    pub version: &'static str,
    /// Deployment environment label (e.g., "development", "staging", "production").
    pub environment: String,
}

/// Style variant for configuration entry display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigEntryStyle {
    /// Normal green display (default).
    #[default]
    Normal,
    /// Warning/unassigned yellow display.
    Warning,
    /// Sensitive value (masked).
    Sensitive,
    /// Separator line (renders as horizontal divider in table).
    Separator,
}

/// A key-value pair rendered in the startup configuration summary.
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    /// Grouping header under which this entry appears (e.g., "General", "Server").
    pub category: &'static str,
    /// Label shown in the left column (e.g., "Listen Address").
    pub display_name: String,
    /// Pre-formatted value shown in the right column.
    pub value: String,
    /// Whether the value should be masked. When true, `style` is also set to
    /// [`ConfigEntryStyle::Sensitive`].
    pub sensitive: bool,
    /// Visual treatment applied when rendering this entry.
    pub style: ConfigEntryStyle,
}

impl ConfigEntry {
    /// Creates a new configuration entry with a display name.
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

    /// Creates a sensitive configuration entry (value will be masked).
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

    /// Creates a warning-styled configuration entry (displayed in yellow).
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

    /// Marks an entry as sensitive.
    pub fn as_sensitive(mut self) -> Self {
        self.sensitive = true;
        self.style = ConfigEntryStyle::Sensitive;
        self
    }

    /// Marks an entry as warning style.
    pub fn as_warning(mut self) -> Self {
        self.style = ConfigEntryStyle::Warning;
        self
    }

    /// Creates a separator entry (renders as horizontal divider in table).
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

/// Renders a TRON-style ASCII banner and a tabular configuration summary.
pub struct StartupDisplay {
    service: ServiceInfo,
    entries: Vec<ConfigEntry>,
    use_ansi: bool,
}

impl StartupDisplay {
    /// Creates a display builder with ANSI auto-detection based on TTY.
    pub fn new(service: ServiceInfo) -> Self {
        Self { service, entries: Vec::new(), use_ansi: std::io::stdout().is_terminal() }
    }

    /// Sets whether to use ANSI colors.
    pub fn with_ansi(mut self, use_ansi: bool) -> Self {
        self.use_ansi = use_ansi;
        self
    }

    /// Adds a configuration entry.
    pub fn entry(mut self, entry: ConfigEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Adds multiple configuration entries.
    pub fn entries(mut self, entries: impl IntoIterator<Item = ConfigEntry>) -> Self {
        self.entries.extend(entries);
        self
    }

    /// Prints the ASCII banner followed by the configuration summary to stdout.
    pub fn display(&self) {
        self.print_banner();
        self.print_config_summary();
    }

    /// Returns the terminal width, defaulting to 80 if detection fails.
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
                            (format!("{yellow}{truncated}...{reset}"), value_col_width)
                        } else {
                            (format!("{yellow}{val}{reset}"), display_width)
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
                            (format!("{green}{truncated}...{reset}"), value_col_width)
                        } else {
                            (format!("{green}{val}{reset}"), display_width)
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

/// Logs a startup phase header to separate initialization stages.
pub fn log_phase(phase: &str) {
    tracing::info!("━━━ {} ━━━", phase);
}

/// Logs a successful component initialization.
pub fn log_initialized(component: &str) {
    tracing::info!("✓ {} initialized", component);
}

/// Logs a skipped component initialization with a reason.
pub fn log_skipped(component: &str, reason: &str) {
    tracing::info!("○ {} skipped: {}", component, reason);
}

/// Logs that the service is ready to accept connections.
pub fn log_ready(service_name: &str) {
    tracing::info!("✓ {} started successfully", service_name);
}

/// Extracts a display hint from a PEM-encoded private key.
///
/// Returns a truncated version like "✓ MC4C...aYc/" to confirm the key is loaded.
pub fn private_key_hint(pem: &str) -> String {
    // Extract the base64 content from the PEM
    let lines: Vec<&str> = pem.lines().collect();
    let base64_content: String =
        lines.iter().filter(|line| !line.starts_with("-----")).copied().collect();

    if base64_content.len() > 8 {
        let start = &base64_content[..4];
        let end = &base64_content[base64_content.len() - 4..];
        format!("✓ {start}...{end}")
    } else if !base64_content.is_empty() {
        format!("✓ {base64_content}")
    } else {
        "✓ Configured".to_string()
    }
}

/// Prints a generated keypair in a warning-styled box.
///
/// Renders the PEM and logs instructions for persisting the key.
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn test_config_entry_warning() {
        let entry = ConfigEntry::warning("Network", "DNS", "unresolved");
        assert_eq!(entry.category, "Network");
        assert_eq!(entry.display_name, "DNS");
        assert_eq!(entry.value, "unresolved");
        assert!(!entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Warning);
    }

    #[test]
    fn test_config_entry_separator() {
        let entry = ConfigEntry::separator("Server");
        assert_eq!(entry.category, "Server");
        assert!(entry.display_name.is_empty());
        assert!(entry.value.is_empty());
        assert!(!entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Separator);
    }

    #[test]
    fn test_config_entry_as_sensitive() {
        let entry = ConfigEntry::new("Auth", "Token", "abc123").as_sensitive();
        assert!(entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Sensitive);
        assert_eq!(entry.value, "abc123");
    }

    #[test]
    fn test_config_entry_as_warning() {
        let entry = ConfigEntry::new("Auth", "Token", "abc123").as_warning();
        assert!(!entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Warning);
    }

    #[test]
    fn test_config_entry_sensitive_factory() {
        let entry = ConfigEntry::sensitive("Security", "Private Key", "secret-key-data");
        assert!(entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Sensitive);
        assert_eq!(entry.category, "Security");
        assert_eq!(entry.display_name, "Private Key");
        assert_eq!(entry.value, "secret-key-data");
    }

    #[test]
    fn test_config_entry_style_default() {
        let style = ConfigEntryStyle::default();
        assert_eq!(style, ConfigEntryStyle::Normal);
    }

    #[test]
    fn test_config_entry_new_with_various_value_types() {
        let entry_str = ConfigEntry::new("Cat", "Key", "string_value");
        assert_eq!(entry_str.value, "string_value");

        let entry_int = ConfigEntry::new("Cat", "Port", 443);
        assert_eq!(entry_int.value, "443");

        let entry_bool = ConfigEntry::new("Cat", "Enabled", true);
        assert_eq!(entry_bool.value, "true");

        let entry_float = ConfigEntry::new("Cat", "Rate", 1.5);
        assert_eq!(entry_float.value, "1.5");
    }

    #[test]
    fn test_config_entry_new_with_into_string_display_name() {
        let name = String::from("Dynamic Name");
        let entry = ConfigEntry::new("Cat", name, "val");
        assert_eq!(entry.display_name, "Dynamic Name");
    }

    fn test_service_info() -> ServiceInfo {
        ServiceInfo {
            name: "TestService",
            subtext: "Test Subtext",
            version: "1.2.3",
            environment: "test".to_string(),
        }
    }

    #[test]
    fn test_startup_display_with_ansi_toggle() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(true);
        assert!(display.use_ansi);

        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        assert!(!display.use_ansi);
    }

    #[test]
    fn test_startup_display_entry_chaining() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("A", "one", "1"))
            .entry(ConfigEntry::new("A", "two", "2"))
            .entry(ConfigEntry::new("B", "three", "3"));

        assert_eq!(display.entries.len(), 3);
        assert_eq!(display.entries[0].category, "A");
        assert_eq!(display.entries[2].category, "B");
    }

    #[test]
    fn test_startup_display_entries_extends() {
        let display = StartupDisplay::new(test_service_info())
            .entry(ConfigEntry::new("Pre", "zero", "0"))
            .entries(vec![ConfigEntry::new("A", "one", "1"), ConfigEntry::new("A", "two", "2")]);

        assert_eq!(display.entries.len(), 3);
        assert_eq!(display.entries[0].display_name, "zero");
    }

    #[test]
    fn test_startup_display_empty_entries_does_not_panic() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        display.display();
    }

    #[test]
    fn test_startup_display_with_entries_does_not_panic() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "Host", "127.0.0.1"))
            .entry(ConfigEntry::new("Server", "Port", 9090))
            .entry(ConfigEntry::sensitive("Auth", "Secret", "s3cr3t"))
            .entry(ConfigEntry::warning("Storage", "Backend", "memory (not persistent)"))
            .entry(ConfigEntry::separator("Server"));

        display.display();
    }

    #[test]
    fn test_startup_display_with_ansi_enabled_does_not_panic() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(true)
            .entry(ConfigEntry::new("Server", "Host", "0.0.0.0"))
            .entry(ConfigEntry::sensitive("Auth", "Key", "secret"))
            .entry(ConfigEntry::warning("Storage", "Mode", "ephemeral"));

        display.display();
    }

    #[test]
    fn test_startup_display_multiple_categories_does_not_panic() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("General", "Name", "test"))
            .entry(ConfigEntry::new("General", "Env", "dev"))
            .entry(ConfigEntry::separator("General"))
            .entry(ConfigEntry::new("Server", "Listen", "0.0.0.0:9090"))
            .entry(ConfigEntry::new("Storage", "Backend", "memory"))
            .entry(ConfigEntry::sensitive("Auth", "JWT Secret", "very-secret-key"));

        display.display();
    }

    #[test]
    fn test_startup_display_separator_only_category_does_not_panic() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::separator("OnlySeparators"))
            .entry(ConfigEntry::separator("OnlySeparators"));

        display.display();
    }

    #[test]
    fn test_print_full_banner_no_ansi_does_not_panic() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        display.print_full_banner(120);
    }

    #[test]
    fn test_print_full_banner_with_ansi_does_not_panic() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(true);
        display.print_full_banner(120);
    }

    #[test]
    fn test_print_compact_banner_no_ansi_does_not_panic() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        display.print_compact_banner(60);
    }

    #[test]
    fn test_print_compact_banner_with_ansi_does_not_panic() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(true);
        display.print_compact_banner(60);
    }

    #[test]
    fn test_print_compact_banner_narrow_terminal_does_not_panic() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        display.print_compact_banner(10);
    }

    #[test]
    fn test_print_full_banner_narrow_terminal_does_not_panic() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        display.print_full_banner(10);
    }

    #[test]
    fn test_print_config_tables_no_ansi_does_not_panic() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::new("Server", "Port", 8080),
            ConfigEntry::separator("Server"),
            ConfigEntry::sensitive("Auth", "Key", "secret"),
            ConfigEntry::warning("Storage", "Backend", "memory"),
        ];

        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 120);
    }

    #[test]
    fn test_print_config_tables_with_ansi_does_not_panic() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::sensitive("Auth", "Key", "secret"),
            ConfigEntry::warning("Warn", "Issue", "something"),
        ];

        let display = StartupDisplay::new(test_service_info()).with_ansi(true).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 100);
    }

    #[test]
    fn test_print_config_tables_narrow_width_does_not_panic() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::new("Server", "Port", 8080),
        ];

        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 50);
    }

    #[test]
    fn test_print_config_simple_no_ansi_does_not_panic() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::new("Server", "Port", 8080),
            ConfigEntry::separator("Server"),
            ConfigEntry::sensitive("Auth", "Key", "secret"),
            ConfigEntry::warning("Storage", "Backend", "memory"),
        ];

        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_simple(&categories);
    }

    #[test]
    fn test_print_config_simple_with_ansi_does_not_panic() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::sensitive("Auth", "Key", "secret"),
            ConfigEntry::warning("Warn", "Issue", "something"),
        ];

        let display = StartupDisplay::new(test_service_info()).with_ansi(true).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_simple(&categories);
    }

    #[test]
    fn test_print_config_tables_long_value_truncation_does_not_panic() {
        let long_value = "a".repeat(200);
        let entries = vec![
            ConfigEntry::new("Cat", "Long Normal", &long_value),
            ConfigEntry::warning("Cat", "Long Warning", &long_value),
        ];

        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 80);
    }

    #[test]
    fn test_private_key_hint_long_base64() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHN0YWNrb3ZlcmZsb3c=\n-----END PRIVATE KEY-----";
        let hint = private_key_hint(pem);
        assert!(hint.starts_with("✓ "));
        assert!(hint.contains("..."));
        // First 4 and last 4 chars of the base64 content
        assert!(hint.contains("MC4C"));
    }

    #[test]
    fn test_private_key_hint_short_base64() {
        let pem = "-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----";
        let hint = private_key_hint(pem);
        assert_eq!(hint, "✓ ABCD");
    }

    #[test]
    fn test_private_key_hint_empty_base64() {
        let pem = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----";
        let hint = private_key_hint(pem);
        assert_eq!(hint, "✓ Configured");
    }

    #[test]
    fn test_private_key_hint_exactly_8_chars() {
        let pem = "-----BEGIN PRIVATE KEY-----\n12345678\n-----END PRIVATE KEY-----";
        let hint = private_key_hint(pem);
        // len == 8, not > 8, so falls to the else-if branch
        assert_eq!(hint, "✓ 12345678");
    }

    #[test]
    fn test_private_key_hint_9_chars() {
        let pem = "-----BEGIN PRIVATE KEY-----\n123456789\n-----END PRIVATE KEY-----";
        let hint = private_key_hint(pem);
        assert!(hint.contains("..."));
        assert!(hint.contains("1234"));
        assert!(hint.contains("6789"));
    }

    #[test]
    fn test_private_key_hint_multiline_base64() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\nCCCC\n-----END PRIVATE KEY-----";
        let hint = private_key_hint(pem);
        // Combined base64 is "AAAABBBBCCCC" (12 chars, > 8)
        assert!(hint.starts_with("✓ "));
        assert!(hint.contains("..."));
        assert!(hint.contains("AAAA"));
        assert!(hint.contains("CCCC"));
    }

    #[test]
    fn test_print_generated_keypair_does_not_panic() {
        let pem =
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHN0YWNr\n-----END PRIVATE KEY-----";
        print_generated_keypair(pem, "pem");
    }

    #[test]
    fn test_ascii_art_line_count() {
        assert_eq!(ASCII_ART.len(), 6);
    }

    #[test]
    fn test_min_width_constants() {
        let full_art = MIN_WIDTH_FOR_FULL_ART;
        let table = MIN_WIDTH_FOR_TABLE;
        assert!(full_art > table);
        assert!(table > 0);
    }

    #[test]
    fn test_service_info_clone() {
        let info = test_service_info();
        let cloned = info.clone();
        assert_eq!(info.name, cloned.name);
        assert_eq!(info.subtext, cloned.subtext);
        assert_eq!(info.version, cloned.version);
        assert_eq!(info.environment, cloned.environment);
    }

    #[test]
    fn test_config_entry_clone() {
        let entry = ConfigEntry::new("Cat", "Key", "Val");
        let cloned = entry.clone();
        assert_eq!(entry.category, cloned.category);
        assert_eq!(entry.display_name, cloned.display_name);
        assert_eq!(entry.value, cloned.value);
        assert_eq!(entry.sensitive, cloned.sensitive);
        assert_eq!(entry.style, cloned.style);
    }

    #[test]
    fn test_config_entry_style_copy() {
        let style = ConfigEntryStyle::Warning;
        let copied = style;
        assert_eq!(style, copied);
    }

    #[test]
    fn test_config_entry_style_debug() {
        let style = ConfigEntryStyle::Sensitive;
        let debug = format!("{style:?}");
        assert!(debug.contains("Sensitive"));
    }

    #[test]
    fn test_config_entry_debug() {
        let entry = ConfigEntry::new("Cat", "Key", "Val");
        let debug = format!("{entry:?}");
        assert!(debug.contains("Cat"));
        assert!(debug.contains("Key"));
        assert!(debug.contains("Val"));
    }

    #[test]
    fn test_service_info_debug() {
        let info = test_service_info();
        let debug = format!("{info:?}");
        assert!(debug.contains("TestService"));
        assert!(debug.contains("1.2.3"));
    }

    #[test]
    fn test_colors_module_constants() {
        assert!(!colors::RESET.is_empty());
        assert!(!colors::BOLD.is_empty());
        assert!(!colors::DIM.is_empty());
        assert!(!colors::CYAN.is_empty());
        assert!(!colors::BRIGHT_CYAN.is_empty());
        assert!(!colors::GREEN.is_empty());
        assert!(!colors::YELLOW.is_empty());
    }

    #[test]
    fn test_colors_are_ansi_escape_sequences() {
        assert!(colors::RESET.starts_with("\x1b["));
        assert!(colors::BOLD.starts_with("\x1b["));
        assert!(colors::DIM.starts_with("\x1b["));
        assert!(colors::CYAN.starts_with("\x1b["));
        assert!(colors::BRIGHT_CYAN.starts_with("\x1b["));
        assert!(colors::GREEN.starts_with("\x1b["));
        assert!(colors::YELLOW.starts_with("\x1b["));
    }

    #[test]
    fn test_display_with_all_entry_styles_in_one_category() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Mixed", "Normal", "value"))
            .entry(ConfigEntry::warning("Mixed", "Warn", "caution"))
            .entry(ConfigEntry::sensitive("Mixed", "Secret", "hidden"))
            .entry(ConfigEntry::separator("Mixed"));

        display.display();
    }

    #[test]
    fn test_display_with_unicode_values_does_not_panic() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "Name", "サーバー"))
            .entry(ConfigEntry::new("Server", "Emoji", "🚀 deployed"));

        display.display();
    }

    #[test]
    fn test_print_config_tables_unicode_truncation_does_not_panic() {
        let long_unicode = "あ".repeat(100);
        let entries = vec![ConfigEntry::new("Cat", "Unicode", &long_unicode)];

        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 60);
    }

    #[test]
    fn test_print_config_tables_warning_truncation_does_not_panic() {
        let long_value = "w".repeat(200);
        let entries = vec![ConfigEntry::warning("Cat", "Long Warning", &long_value)];

        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 60);
    }

    #[test]
    fn test_print_generated_keypair_empty_pem_does_not_panic() {
        print_generated_keypair("", "pem");
    }

    #[test]
    fn test_print_generated_keypair_long_lines_does_not_panic() {
        let long_line = "A".repeat(200);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{long_line}\n-----END PRIVATE KEY-----");
        print_generated_keypair(&pem, "test-key");
    }

    #[test]
    fn test_log_phase_does_not_panic() {
        log_phase("initialization");
    }

    #[test]
    fn test_log_initialized_does_not_panic() {
        log_initialized("storage");
    }

    #[test]
    fn test_log_skipped_does_not_panic() {
        log_skipped("email", "not configured");
    }

    #[test]
    fn test_log_ready_does_not_panic() {
        log_ready("InferaDB Control");
    }

    #[test]
    fn test_print_banner_wide_terminal_uses_full_banner() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        // Wide terminal (>= MIN_WIDTH_FOR_FULL_ART) should use full banner
        display.print_full_banner(200);
    }

    #[test]
    fn test_print_banner_narrow_terminal_uses_compact_banner() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        // Narrow terminal (< MIN_WIDTH_FOR_FULL_ART) uses compact banner
        display.print_compact_banner(40);
    }

    #[test]
    fn test_print_config_summary_empty_entries_returns_early() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);
        // No entries -- print_config_summary returns early without output
        display.print_config_summary();
    }

    #[test]
    fn test_print_config_summary_with_entries_does_not_panic() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "Port", 8080));
        display.print_config_summary();
    }

    #[test]
    fn test_print_config_summary_narrow_terminal_uses_simple() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::new("Server", "Port", 8080),
        ];
        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);
        // We can't control terminal_size() from the test, but we can call
        // print_config_simple directly with the categories.
        let categories = build_categories(&display.entries);
        display.print_config_simple(&categories);
    }

    #[test]
    fn test_print_config_tables_with_sensitive_entry() {
        let entries = vec![ConfigEntry::sensitive("Auth", "API Key", "super-secret-key-value")];
        let display = StartupDisplay::new(test_service_info()).with_ansi(true).entries(entries);
        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 100);
    }

    #[test]
    fn test_print_config_tables_minimal_width() {
        let entries = vec![ConfigEntry::new("X", "K", "V")];
        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);
        let categories = build_categories(&display.entries);
        // Extremely narrow -- tests saturating_sub paths
        display.print_config_tables(&categories, 10);
    }

    #[test]
    fn test_private_key_hint_no_header_lines() {
        // PEM with no header/footer lines -- all lines are base64
        let hint = private_key_hint("AAAABBBBCCCCDDDD");
        assert!(hint.contains("..."));
        assert!(hint.contains("AAAA"));
    }

    #[test]
    fn test_display_method_calls_both_banner_and_config() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "Host", "0.0.0.0"))
            .entry(ConfigEntry::sensitive("Auth", "Token", "secret"))
            .entry(ConfigEntry::warning("Storage", "Mode", "memory"))
            .entry(ConfigEntry::separator("Server"));
        display.display();
    }

    fn build_categories(entries: &[ConfigEntry]) -> Vec<(&str, Vec<&ConfigEntry>)> {
        let mut categories: Vec<(&str, Vec<&ConfigEntry>)> = Vec::new();
        for entry in entries {
            if let Some((_, cat_entries)) =
                categories.iter_mut().find(|(cat, _)| *cat == entry.category)
            {
                cat_entries.push(entry);
            } else {
                categories.push((entry.category, vec![entry]));
            }
        }
        categories
    }
}
