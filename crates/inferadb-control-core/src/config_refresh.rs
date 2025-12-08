//! Dynamic configuration refresh with file watching and env var polling
//!
//! This module provides functionality to automatically refresh configuration
//! when the config file changes or when environment variables are updated.
//!
//! - Config file changes are detected using file system watching (notify crate)
//! - Environment variable changes are detected via periodic polling
//!
//! This is particularly useful in Kubernetes environments where ConfigMaps
//! can be updated and mounted as files or reflected as environment variable changes.

use std::{path::PathBuf, sync::Arc, time::Duration};

use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use parking_lot::RwLock;
use tokio::{sync::mpsc, time::interval};
use tracing::{debug, error, info, warn};

use crate::config::ManagementConfig;

/// Configuration refresher that watches files and polls environment variables
pub struct ConfigRefresher {
    /// Current configuration (protected by RwLock for concurrent access)
    config: Arc<RwLock<ManagementConfig>>,
    /// Path to config file
    config_path: PathBuf,
    /// How often to check for environment variable changes (polling interval)
    env_poll_interval: Duration,
}

impl ConfigRefresher {
    /// Create a new configuration refresher
    ///
    /// # Arguments
    ///
    /// * `config` - Shared reference to the current configuration
    /// * `config_path` - Path to the config file (will be watched for changes)
    /// * `env_poll_interval_secs` - How often to poll for environment variable changes (in seconds)
    pub fn new(
        config: Arc<RwLock<ManagementConfig>>,
        config_path: PathBuf,
        env_poll_interval_secs: u64,
    ) -> Self {
        Self { config, config_path, env_poll_interval: Duration::from_secs(env_poll_interval_secs) }
    }

    /// Spawn the background refresh task
    ///
    /// This creates:
    /// 1. A file watcher that automatically reloads when the config file changes
    /// 2. A background task that periodically polls for environment variable changes
    ///
    /// The tasks run indefinitely until the program exits or is cancelled.
    pub fn spawn(self: Arc<Self>) {
        info!(
            config_path = ?self.config_path,
            env_poll_interval_secs = self.env_poll_interval.as_secs(),
            "Spawning configuration refresh task with file watching and env var polling"
        );

        let config_path_clone = self.config_path.clone();

        // Channel for file change events
        let (tx, mut rx) = mpsc::channel(100);

        // Spawn file watcher in a separate thread (notify requires std::sync)
        std::thread::spawn(move || {
            let rt = tokio::runtime::Handle::current();
            let config_file_name =
                config_path_clone.file_name().and_then(|n| n.to_str()).map(|s| s.to_string());

            let mut watcher = match RecommendedWatcher::new(
                move |res: Result<Event, notify::Error>| {
                    match res {
                        Ok(event) => {
                            // Only trigger on modify/create events
                            // Filter by config file name if we're watching the parent directory
                            let should_trigger = if let Some(ref file_name) = config_file_name {
                                event.paths.iter().any(|p| {
                                    p.file_name().and_then(|n| n.to_str()) == Some(file_name)
                                }) && matches!(
                                    event.kind,
                                    EventKind::Modify(_) | EventKind::Create(_)
                                )
                            } else {
                                matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
                            };

                            if should_trigger {
                                // Send notification (ignore errors if channel is closed)
                                let _ = rt.block_on(tx.send(()));
                            }
                        },
                        Err(e) => error!(error = %e, "File watch error"),
                    }
                },
                NotifyConfig::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    error!(error = %e, "Failed to create file watcher");
                    return;
                },
            };

            // Try to watch the config file directly if it exists
            // Otherwise, watch the parent directory to detect when the file is created
            let watch_path = if config_path_clone.exists() {
                info!("Config file exists, watching directly: {:?}", config_path_clone);
                config_path_clone.clone()
            } else if let Some(parent) = config_path_clone.parent() {
                info!("Config file doesn't exist, watching parent directory: {:?}", parent);
                parent.to_path_buf()
            } else {
                error!(
                    "Cannot determine parent directory for config file: {:?}",
                    config_path_clone
                );
                return;
            };

            if let Err(e) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
                error!(error = %e, path = ?watch_path, "Failed to watch path");
                return;
            }

            info!("File watcher started for {:?}", watch_path);

            // Keep watcher alive by parking the thread indefinitely
            // The watcher will be dropped when the program exits
            loop {
                std::thread::park();
            }
        });

        // Spawn async task to handle file changes and env var polling
        tokio::spawn(async move {
            let mut env_timer = interval(self.env_poll_interval);

            loop {
                tokio::select! {
                    // File change event
                    Some(_) = rx.recv() => {
                        debug!("Config file changed, reloading");
                        self.reload_config("file change").await;
                    }
                    // Environment variable poll
                    _ = env_timer.tick() => {
                        debug!("Polling for environment variable changes");
                        self.reload_config("env var poll").await;
                    }
                }
            }
        });
    }

    /// Reload configuration and apply if changed
    async fn reload_config(&self, trigger: &str) {
        match ManagementConfig::load(&self.config_path) {
            Ok(new_config) => {
                // Check if configuration actually changed
                let changed = {
                    let current = self.config.read();
                    !configs_equal(&current, &new_config)
                };

                if changed {
                    info!(trigger = trigger, "Configuration changed, applying updates");

                    // Validate new configuration before applying
                    if let Err(e) = new_config.validate() {
                        warn!(
                            error = %e,
                            "New configuration is invalid, keeping current config"
                        );
                        return;
                    }

                    // Update configuration
                    let mut current = self.config.write();
                    *current = new_config;

                    info!("Configuration successfully refreshed");
                } else {
                    debug!(trigger = trigger, "No configuration changes detected");
                }
            },
            Err(e) => {
                warn!(
                    error = %e,
                    trigger = trigger,
                    "Failed to reload configuration, keeping current config"
                );
            },
        }
    }

    /// Perform an immediate refresh (useful for testing)
    ///
    /// This does not spawn a background task, but performs a single refresh operation.
    pub async fn refresh_once(&self) -> Result<bool, Box<dyn std::error::Error>> {
        debug!("Performing one-time configuration refresh");

        let new_config = ManagementConfig::load(&self.config_path)?;

        // Check if configuration changed
        let changed = {
            let current = self.config.read();
            !configs_equal(&current, &new_config)
        };

        if changed {
            info!("Configuration changed during refresh");

            // Validate before applying
            new_config.validate()?;

            // Update configuration
            let mut current = self.config.write();
            *current = new_config;

            info!("Configuration successfully refreshed");
            Ok(true)
        } else {
            debug!("No configuration changes detected");
            Ok(false)
        }
    }
}

/// Compare two configurations for equality (excluding volatile fields)
///
/// Note: This is a simplified comparison that serializes to JSON and compares.
/// For production use, you may want to implement custom comparison logic that
/// ignores specific fields or only compares critical configuration values.
fn configs_equal(a: &ManagementConfig, b: &ManagementConfig) -> bool {
    // Simple approach: serialize both and compare JSON
    // This will detect any field changes
    match (serde_json::to_value(a), serde_json::to_value(b)) {
        (Ok(a_json), Ok(b_json)) => a_json == b_json,
        _ => false, // If serialization fails, assume they're different
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[tokio::test]
    async fn test_refresh_once_no_changes() {
        // Create a temporary config file with .yaml extension
        let temp_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        let config_path = temp_file.path().to_path_buf();

        // Write initial config with storage backend
        fs::write(
            &config_path,
            r#"
server:
  http_port: 3001
storage:
  storage_type: "memory"
"#,
        )
        .unwrap();

        // Load initial config
        let initial_config = ManagementConfig::load(&config_path).unwrap();
        let config = Arc::new(RwLock::new(initial_config));

        // Create refresher
        let refresher = ConfigRefresher::new(config.clone(), config_path, 30);

        // Refresh should detect no changes
        let changed = refresher.refresh_once().await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn test_refresh_once_with_changes() {
        // Create a temporary config file with .yaml extension
        let temp_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        let config_path = temp_file.path().to_path_buf();

        // Write initial config with storage backend specified
        fs::write(
            &config_path,
            r#"
server:
  public_rest: "0.0.0.0:3001"
storage:
  storage_type: "memory"
auth:
  webauthn:
    rp_id: "localhost"
    origin: "http://localhost:3000"
server_api:
  grpc_endpoint: "http://localhost:8080"
"#,
        )
        .unwrap();

        // Load initial config
        let initial_config = ManagementConfig::load(&config_path).unwrap();
        let config = Arc::new(RwLock::new(initial_config));

        // Verify initial address
        assert_eq!(config.read().server.public_rest, "0.0.0.0:3001");

        // Modify config file with a different address
        fs::write(
            &config_path,
            r#"
server:
  public_rest: "0.0.0.0:3002"
storage:
  storage_type: "memory"
auth:
  webauthn:
    rp_id: "localhost"
    origin: "http://localhost:3000"
server_api:
  grpc_endpoint: "http://localhost:8080"
"#,
        )
        .unwrap();

        // Create refresher
        let refresher = ConfigRefresher::new(config.clone(), config_path, 30);

        // Refresh should detect changes
        let changed = refresher.refresh_once().await.unwrap();
        assert!(changed, "Config should have changed");

        // Verify address was updated
        let current = config.read();
        assert_eq!(
            current.server.public_rest, "0.0.0.0:3002",
            "Address should be updated to 0.0.0.0:3002"
        );
    }

    #[tokio::test]
    async fn test_refresh_rejects_invalid_config() {
        // Create a temporary config file with .yaml extension
        let temp_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        let config_path = temp_file.path().to_path_buf();

        // Write initial valid config
        fs::write(
            &config_path,
            r#"
server:
  public_rest: "0.0.0.0:3001"
storage:
  storage_type: "memory"
"#,
        )
        .unwrap();

        // Load initial config
        let initial_config = ManagementConfig::load(&config_path).unwrap();
        let config = Arc::new(RwLock::new(initial_config));

        // Verify initial values
        assert_eq!(config.read().server.public_rest, "0.0.0.0:3001");

        // Write invalid config (invalid address format)
        fs::write(
            &config_path,
            r#"
server:
  public_rest: "invalid-address"
storage:
  storage_type: "memory"
"#,
        )
        .unwrap();

        // Create refresher
        let refresher = ConfigRefresher::new(config.clone(), config_path, 30);

        // Refresh should fail validation (invalid address)
        let result = refresher.refresh_once().await;
        assert!(result.is_err(), "Should reject invalid address");

        // Verify config was not changed (should still be valid)
        let current = config.read();
        assert_eq!(current.server.public_rest, "0.0.0.0:3001");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_spawn_task() {
        // Create a temporary config file with .yaml extension
        let temp_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        let config_path = temp_file.path().to_path_buf();

        // Write initial config with storage backend
        fs::write(
            &config_path,
            r#"
server:
  public_rest: "0.0.0.0:3001"
storage:
  storage_type: "memory"
auth:
  webauthn:
    rp_id: "localhost"
    origin: "http://localhost:3000"
server_api:
  grpc_endpoint: "http://localhost:8080"
"#,
        )
        .unwrap();

        // Load initial config
        let initial_config = ManagementConfig::load(&config_path).unwrap();
        let config = Arc::new(RwLock::new(initial_config));

        // Verify initial address
        assert_eq!(config.read().server.public_rest, "0.0.0.0:3001");

        // Create and spawn refresher with 1 second interval
        let refresher = Arc::new(ConfigRefresher::new(config.clone(), config_path.clone(), 1));
        refresher.spawn();

        // Wait a bit then modify config
        tokio::time::sleep(Duration::from_millis(500)).await;

        fs::write(
            &config_path,
            r#"
server:
  public_rest: "0.0.0.0:3002"
storage:
  storage_type: "memory"
auth:
  webauthn:
    rp_id: "localhost"
    origin: "http://localhost:3000"
server_api:
  grpc_endpoint: "http://localhost:8080"
"#,
        )
        .unwrap();

        // Wait for refresh to happen (1 second interval + some buffer)
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // Verify config was updated
        let current = config.read();
        assert_eq!(
            current.server.public_rest, "0.0.0.0:3002",
            "Address should be updated to 0.0.0.0:3002"
        );
    }
}
