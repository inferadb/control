//! Startup display utilities for InferaDB services
//!
//! Provides consistent, structured startup output across all InferaDB binaries.
//! Includes TRON-style ASCII art banner and configuration summary formatting.

use std::io::IsTerminal;

use terminal_size::{Width, terminal_size};

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

/// Service information for the startup banner
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service name (e.g., "InferaDB Management API")
    pub name: &'static str,
    /// Service subtext (e.g., "Management API Server")
    pub subtext: &'static str,
    /// Version string
    pub version: &'static str,
    /// Environment (development, staging, production)
    pub environment: String,
}

/// A single configuration entry for display
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    /// Category/group name
    pub category: &'static str,
    /// Configuration key
    pub key: &'static str,
    /// Configuration value (already formatted as string)
    pub value: String,
    /// Whether this is a sensitive value that should be masked
    pub sensitive: bool,
}

impl ConfigEntry {
    /// Create a new configuration entry
    pub fn new(category: &'static str, key: &'static str, value: impl ToString) -> Self {
        Self { category, key, value: value.to_string(), sensitive: false }
    }

    /// Create a sensitive configuration entry (value will be masked)
    pub fn sensitive(category: &'static str, key: &'static str, value: impl ToString) -> Self {
        Self { category, key, value: value.to_string(), sensitive: true }
    }

    /// Mark an entry as sensitive
    pub fn as_sensitive(mut self) -> Self {
        self.sensitive = true;
        self
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
    fn get_terminal_width() -> usize {
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
        let (reset, bold, dim, bright_cyan, cyan) = if self.use_ansi {
            (colors::RESET, colors::BOLD, colors::DIM, colors::BRIGHT_CYAN, colors::CYAN)
        } else {
            ("", "", "", "", "")
        };

        // Calculate box width (art width + padding + borders)
        let inner_width = ASCII_ART_WIDTH + 4; // 2 spaces padding on each side
        let box_width = inner_width.min(terminal_width.saturating_sub(2));

        // Calculate left padding to center the box
        let box_left_pad = if terminal_width > box_width + 2 {
            (terminal_width - box_width - 2) / 2
        } else {
            0
        };
        let box_indent = " ".repeat(box_left_pad);

        // Calculate padding inside the box to center the ASCII art
        let art_left_pad = if box_width > ASCII_ART_WIDTH + 2 {
            (box_width - ASCII_ART_WIDTH - 2) / 2
        } else {
            1
        };
        let art_indent = " ".repeat(art_left_pad);

        println!();

        // Top border
        println!(
            "{box_indent}{cyan}╔{border}╗{reset}",
            border = "═".repeat(box_width)
        );

        // Empty line
        println!(
            "{box_indent}{cyan}║{reset}{spaces}{cyan}║{reset}",
            spaces = " ".repeat(box_width)
        );

        // ASCII art lines
        for line in ASCII_ART {
            let right_pad = box_width.saturating_sub(art_left_pad + ASCII_ART_WIDTH);
            println!(
                "{box_indent}{cyan}║{reset}{art_indent}{bold}{bright_cyan}{line}{reset}{right_pad}{cyan}║{reset}",
                right_pad = " ".repeat(right_pad)
            );
        }

        // Empty line
        println!(
            "{box_indent}{cyan}║{reset}{spaces}{cyan}║{reset}",
            spaces = " ".repeat(box_width)
        );

        // Subtext (centered)
        let subtext = self.service.subtext;
        let subtext_left_pad = (box_width.saturating_sub(subtext.len())) / 2;
        let subtext_right_pad = box_width.saturating_sub(subtext_left_pad + subtext.len());
        println!(
            "{box_indent}{cyan}║{reset}{left_pad}{dim}{subtext}{reset}{right_pad}{cyan}║{reset}",
            left_pad = " ".repeat(subtext_left_pad),
            right_pad = " ".repeat(subtext_right_pad)
        );

        // Version (centered)
        let version_str = format!("v{}", self.service.version);
        let version_left_pad = (box_width.saturating_sub(version_str.len())) / 2;
        let version_right_pad = box_width.saturating_sub(version_left_pad + version_str.len());
        println!(
            "{box_indent}{cyan}║{reset}{left_pad}{dim}{version_str}{reset}{right_pad}{cyan}║{reset}",
            left_pad = " ".repeat(version_left_pad),
            right_pad = " ".repeat(version_right_pad)
        );

        // Empty line
        println!(
            "{box_indent}{cyan}║{reset}{spaces}{cyan}║{reset}",
            spaces = " ".repeat(box_width)
        );

        // Bottom border
        println!(
            "{box_indent}{cyan}╚{border}╝{reset}",
            border = "═".repeat(box_width)
        );

        println!();
    }

    fn print_compact_banner(&self, terminal_width: usize) {
        let (reset, bold, dim, bright_cyan, cyan) = if self.use_ansi {
            (colors::RESET, colors::BOLD, colors::DIM, colors::BRIGHT_CYAN, colors::CYAN)
        } else {
            ("", "", "", "", "")
        };

        // Calculate box width
        let box_width = terminal_width.saturating_sub(4).max(30);

        println!();

        // Top border
        println!("{cyan}╔{border}╗{reset}", border = "═".repeat(box_width));

        // Title line with decorative elements
        let title = "▀▀▀ INFERADB ▀▀▀";
        let title_left_pad = (box_width.saturating_sub(title.len())) / 2;
        let title_right_pad = box_width.saturating_sub(title_left_pad + title.len());
        println!(
            "{cyan}║{reset}{left_pad}{bold}{bright_cyan}{title}{reset}{right_pad}{cyan}║{reset}",
            left_pad = " ".repeat(title_left_pad),
            right_pad = " ".repeat(title_right_pad)
        );

        // Subtext (centered)
        let subtext = self.service.subtext;
        let subtext_left_pad = (box_width.saturating_sub(subtext.len())) / 2;
        let subtext_right_pad = box_width.saturating_sub(subtext_left_pad + subtext.len());
        println!(
            "{cyan}║{reset}{left_pad}{dim}{subtext}{reset}{right_pad}{cyan}║{reset}",
            left_pad = " ".repeat(subtext_left_pad),
            right_pad = " ".repeat(subtext_right_pad)
        );

        // Version (centered)
        let version_str = format!("v{}", self.service.version);
        let version_left_pad = (box_width.saturating_sub(version_str.len())) / 2;
        let version_right_pad = box_width.saturating_sub(version_left_pad + version_str.len());
        println!(
            "{cyan}║{reset}{left_pad}{dim}{version_str}{reset}{right_pad}{cyan}║{reset}",
            left_pad = " ".repeat(version_left_pad),
            right_pad = " ".repeat(version_right_pad)
        );

        // Bottom border
        println!("{cyan}╚{border}╝{reset}", border = "═".repeat(box_width));

        println!();
    }

    fn print_config_summary(&self) {
        if self.entries.is_empty() {
            return;
        }

        let (dim, reset, bold, green, yellow) = if self.use_ansi {
            (colors::DIM, colors::RESET, colors::BOLD, colors::GREEN, colors::YELLOW)
        } else {
            ("", "", "", "", "")
        };

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

        // Calculate column width for alignment
        let max_key_len = self.entries.iter().map(|e| e.key.len()).max().unwrap_or(20).max(20);

        println!("{bold}Configuration:{reset}");
        println!();

        for (category, entries) in categories {
            println!("  {dim}[{category}]{reset}");
            for entry in entries {
                let display_value = if entry.sensitive {
                    format!("{yellow}********{reset}")
                } else {
                    format!("{green}{}{reset}", entry.value)
                };
                println!(
                    "    {key:<width$}  {value}",
                    key = entry.key,
                    width = max_key_len,
                    value = display_value
                );
            }
            println!();
        }
    }
}

/// Log a startup phase header
///
/// Use this to clearly delineate initialization phases in the logs.
pub fn log_phase(phase: &str) {
    tracing::info!("");
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
pub fn log_ready(service: &str, addresses: &[(&str, &str)]) {
    tracing::info!("");
    tracing::info!("━━━ {} Ready ━━━", service);
    for (name, addr) in addresses {
        tracing::info!("  {} → {}", name, addr);
    }
    tracing::info!("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_entry_creation() {
        let entry = ConfigEntry::new("Server", "port", 8080);
        assert_eq!(entry.category, "Server");
        assert_eq!(entry.key, "port");
        assert_eq!(entry.value, "8080");
        assert!(!entry.sensitive);
    }

    #[test]
    fn test_sensitive_entry() {
        let entry = ConfigEntry::sensitive("Auth", "secret", "my-secret");
        assert!(entry.sensitive);

        let entry2 = ConfigEntry::new("Auth", "key", "value").as_sensitive();
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
            .entry(ConfigEntry::new("Server", "host", "0.0.0.0"))
            .entry(ConfigEntry::new("Server", "port", 8080));

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
            ConfigEntry::new("Server", "host", "0.0.0.0"),
            ConfigEntry::new("Server", "port", 8080),
            ConfigEntry::new("Storage", "backend", "memory"),
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
