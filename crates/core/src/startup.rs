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

    /// Marks an entry with warning style.
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

/// Logs a labeled header to visually separate startup sections.
pub fn log_phase(phase: &str) {
    tracing::info!("━━━ {} ━━━", phase);
}

/// Logs that a component initialized successfully.
pub fn log_initialized(component: &str) {
    tracing::info!("✓ {} initialized", component);
}

/// Logs that a component was skipped during startup, with a reason.
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

    fn test_service_info() -> ServiceInfo {
        ServiceInfo {
            name: "TestService",
            subtext: "Test Subtext",
            version: "1.2.3",
            environment: "test".to_string(),
        }
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

    // ── ConfigEntry factories ──

    #[test]
    fn test_config_entry_new_sets_fields_and_normal_style() {
        let entry = ConfigEntry::new("Server", "Port", 8080);

        assert_eq!(entry.category, "Server");
        assert_eq!(entry.display_name, "Port");
        assert_eq!(entry.value, "8080");
        assert!(!entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Normal);
    }

    #[test]
    fn test_config_entry_new_accepts_various_value_types() {
        let cases: &[(&str, &str)] =
            &[("string_value", "string_value"), ("443", "443"), ("true", "true"), ("1.5", "1.5")];

        let entries = [
            ConfigEntry::new("Cat", "Key", "string_value"),
            ConfigEntry::new("Cat", "Port", 443),
            ConfigEntry::new("Cat", "Enabled", true),
            ConfigEntry::new("Cat", "Rate", 1.5),
        ];

        for (entry, (_, expected)) in entries.iter().zip(cases) {
            assert_eq!(entry.value, *expected);
        }
    }

    #[test]
    fn test_config_entry_new_accepts_owned_string_display_name() {
        let name = String::from("Dynamic Name");

        let entry = ConfigEntry::new("Cat", name, "val");

        assert_eq!(entry.display_name, "Dynamic Name");
    }

    #[test]
    fn test_config_entry_sensitive_factory_sets_sensitive_style() {
        let entry = ConfigEntry::sensitive("Security", "Private Key", "secret-key-data");

        assert!(entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Sensitive);
        assert_eq!(entry.category, "Security");
        assert_eq!(entry.display_name, "Private Key");
        assert_eq!(entry.value, "secret-key-data");
    }

    #[test]
    fn test_config_entry_warning_factory_sets_warning_style() {
        let entry = ConfigEntry::warning("Network", "DNS", "unresolved");

        assert_eq!(entry.style, ConfigEntryStyle::Warning);
        assert!(!entry.sensitive);
        assert_eq!(entry.value, "unresolved");
    }

    #[test]
    fn test_config_entry_separator_creates_empty_divider() {
        let entry = ConfigEntry::separator("Server");

        assert_eq!(entry.category, "Server");
        assert!(entry.display_name.is_empty());
        assert!(entry.value.is_empty());
        assert_eq!(entry.style, ConfigEntryStyle::Separator);
    }

    #[test]
    fn test_config_entry_as_sensitive_converts_normal_to_sensitive() {
        let entry = ConfigEntry::new("Auth", "Token", "abc123").as_sensitive();

        assert!(entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Sensitive);
        assert_eq!(entry.value, "abc123");
    }

    #[test]
    fn test_config_entry_as_warning_converts_normal_to_warning() {
        let entry = ConfigEntry::new("Auth", "Token", "abc123").as_warning();

        assert!(!entry.sensitive);
        assert_eq!(entry.style, ConfigEntryStyle::Warning);
    }

    #[test]
    fn test_config_entry_style_default_is_normal() {
        assert_eq!(ConfigEntryStyle::default(), ConfigEntryStyle::Normal);
    }

    // ── ASCII art consistency ──

    #[test]
    fn test_ascii_art_lines_match_declared_width() {
        for (i, line) in ASCII_ART.iter().enumerate() {
            assert_eq!(
                line.chars().count(),
                ASCII_ART_WIDTH,
                "ASCII art line {i} has inconsistent width"
            );
        }
    }

    // ── StartupDisplay builder ──

    #[test]
    fn test_startup_display_builder_accumulates_entries() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("A", "one", "1"))
            .entry(ConfigEntry::new("A", "two", "2"))
            .entry(ConfigEntry::new("B", "three", "3"));

        assert_eq!(display.entries.len(), 3);
        assert!(!display.use_ansi);
        assert_eq!(display.entries[0].category, "A");
        assert_eq!(display.entries[2].category, "B");
    }

    #[test]
    fn test_startup_display_entries_extends_existing() {
        let display = StartupDisplay::new(test_service_info())
            .entry(ConfigEntry::new("Pre", "zero", "0"))
            .entries(vec![ConfigEntry::new("A", "one", "1"), ConfigEntry::new("A", "two", "2")]);

        assert_eq!(display.entries.len(), 3);
        assert_eq!(display.entries[0].display_name, "zero");
    }

    #[test]
    fn test_startup_display_with_ansi_toggle() {
        let on = StartupDisplay::new(test_service_info()).with_ansi(true);
        let off = StartupDisplay::new(test_service_info()).with_ansi(false);

        assert!(on.use_ansi);
        assert!(!off.use_ansi);
    }

    #[test]
    fn test_terminal_width_returns_positive() {
        let width = StartupDisplay::get_terminal_width();

        assert!(width > 0);
    }

    // ── Display rendering (smoke tests for no-panic across code paths) ──

    #[test]
    fn test_display_all_entry_styles_no_ansi() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Mixed", "Normal", "value"))
            .entry(ConfigEntry::warning("Mixed", "Warn", "caution"))
            .entry(ConfigEntry::sensitive("Mixed", "Secret", "hidden"))
            .entry(ConfigEntry::separator("Mixed"));

        display.display();
    }

    #[test]
    fn test_display_all_entry_styles_with_ansi() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(true)
            .entry(ConfigEntry::new("Server", "Host", "0.0.0.0"))
            .entry(ConfigEntry::sensitive("Auth", "Key", "secret"))
            .entry(ConfigEntry::warning("Storage", "Mode", "ephemeral"));

        display.display();
    }

    #[test]
    fn test_display_multiple_categories() {
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
    fn test_display_empty_entries() {
        StartupDisplay::new(test_service_info()).with_ansi(false).display();
    }

    #[test]
    fn test_display_separator_only_category() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::separator("OnlySeparators"))
            .entry(ConfigEntry::separator("OnlySeparators"));

        display.display();
    }

    #[test]
    fn test_display_unicode_values() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "Name", "サーバー"))
            .entry(ConfigEntry::new("Server", "Emoji", "🚀 deployed"));

        display.display();
    }

    // ── Banner rendering at various widths ──

    #[test]
    fn test_full_banner_renders_at_various_widths() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);

        for width in [10, 80, 120, 200] {
            display.print_full_banner(width);
        }
    }

    #[test]
    fn test_full_banner_with_ansi() {
        StartupDisplay::new(test_service_info()).with_ansi(true).print_full_banner(120);
    }

    #[test]
    fn test_compact_banner_renders_at_various_widths() {
        let display = StartupDisplay::new(test_service_info()).with_ansi(false);

        for width in [10, 40, 60] {
            display.print_compact_banner(width);
        }
    }

    #[test]
    fn test_compact_banner_with_ansi() {
        StartupDisplay::new(test_service_info()).with_ansi(true).print_compact_banner(60);
    }

    // ── Config table rendering ──

    #[test]
    fn test_config_tables_all_styles_no_ansi() {
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
    fn test_config_tables_with_ansi() {
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
    fn test_config_tables_truncation_paths() {
        let long_value = "a".repeat(200);
        let long_unicode = "あ".repeat(100);
        let long_warning = "w".repeat(200);
        let entries = vec![
            ConfigEntry::new("Cat", "Long Normal", &long_value),
            ConfigEntry::warning("Cat", "Long Warning", &long_warning),
            ConfigEntry::new("Cat", "Long Unicode", &long_unicode),
        ];
        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 60);
    }

    #[test]
    fn test_config_tables_minimal_width() {
        let entries = vec![ConfigEntry::new("X", "K", "V")];
        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_tables(&categories, 10);
    }

    // ── Config simple rendering ──

    #[test]
    fn test_config_simple_all_styles() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::separator("Server"),
            ConfigEntry::sensitive("Auth", "Key", "secret"),
            ConfigEntry::warning("Storage", "Backend", "memory"),
        ];
        let display = StartupDisplay::new(test_service_info()).with_ansi(false).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_simple(&categories);
    }

    #[test]
    fn test_config_simple_with_ansi() {
        let entries = vec![
            ConfigEntry::new("Server", "Host", "localhost"),
            ConfigEntry::sensitive("Auth", "Key", "secret"),
        ];
        let display = StartupDisplay::new(test_service_info()).with_ansi(true).entries(entries);

        let categories = build_categories(&display.entries);
        display.print_config_simple(&categories);
    }

    // ── Config summary dispatch ──

    #[test]
    fn test_config_summary_empty_returns_early() {
        StartupDisplay::new(test_service_info()).with_ansi(false).print_config_summary();
    }

    #[test]
    fn test_config_summary_with_entries() {
        let display = StartupDisplay::new(test_service_info())
            .with_ansi(false)
            .entry(ConfigEntry::new("Server", "Port", 8080));

        display.print_config_summary();
    }

    // ── private_key_hint (table-driven) ──

    #[test]
    fn test_private_key_hint_cases() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHN0YWNrb3ZlcmZsb3c=\n-----END PRIVATE KEY-----",
                "MC4C",
                "long base64 truncates with first/last 4 chars",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----",
                "✓ ABCD",
                "short base64 shows full content",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
                "✓ Configured",
                "empty base64 shows configured",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\n12345678\n-----END PRIVATE KEY-----",
                "✓ 12345678",
                "exactly 8 chars shows full content",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\n123456789\n-----END PRIVATE KEY-----",
                "1234",
                "9 chars truncates",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\nCCCC\n-----END PRIVATE KEY-----",
                "AAAA",
                "multiline base64 concatenated",
            ),
            ("AAAABBBBCCCCDDDD", "AAAA", "no header lines"),
        ];

        for (pem, expected_substr, label) in cases {
            let hint = private_key_hint(pem);
            assert!(
                hint.contains(expected_substr),
                "[{label}] hint={hint:?} should contain {expected_substr:?}"
            );
        }
    }

    // ── print_generated_keypair ──

    #[test]
    fn test_print_generated_keypair_various_inputs() {
        let cases = [
            (
                "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHN0YWNr\n-----END PRIVATE KEY-----",
                "pem",
            ),
            ("", "pem"),
            (
                &format!(
                    "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                    "A".repeat(200)
                ),
                "test-key",
            ),
        ];

        for (pem, key) in cases {
            print_generated_keypair(pem, key);
        }
    }

    // ── Log helper functions ──

    #[test]
    fn test_log_helpers_do_not_panic() {
        log_phase("initialization");
        log_initialized("storage");
        log_skipped("email", "not configured");
        log_ready("InferaDB Control");
    }
}
