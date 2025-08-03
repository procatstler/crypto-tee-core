//! Plugin system for extending CryptoTEE functionality

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::{error::CryptoTEEResult, types::OperationContext};

/// Trait for CryptoTEE plugins
#[async_trait]
pub trait CryptoPlugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> &str;

    /// Get the plugin version
    fn version(&self) -> &str;

    /// Initialize the plugin
    async fn initialize(&mut self, context: PluginContext) -> CryptoTEEResult<()>;

    /// Shutdown the plugin
    async fn shutdown(&mut self) -> CryptoTEEResult<()> {
        Ok(())
    }

    /// Get the operations this plugin extends
    fn operations(&self) -> Vec<Operation>;
}

/// Plugin context provided during initialization
#[derive(Clone)]
pub struct PluginContext {
    /// Plugin configuration
    pub config: serde_json::Value,
}

/// Operation definition
pub struct Operation {
    /// Operation name
    pub name: String,

    /// Operation handler
    pub handler: Arc<dyn OperationHandler>,
}

/// Handler for plugin operations
#[async_trait]
pub trait OperationHandler: Send + Sync {
    /// Handle the operation
    async fn handle(&self, context: &OperationContext) -> CryptoTEEResult<serde_json::Value>;
}

/// Plugin manager
pub struct PluginManager {
    plugins: Vec<Box<dyn CryptoPlugin>>,
    operations: HashMap<String, Arc<dyn OperationHandler>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self { plugins: Vec::new(), operations: HashMap::new() }
    }

    /// Register a plugin
    pub fn register(&mut self, plugin: Box<dyn CryptoPlugin>) {
        info!("Registering plugin: {} v{}", plugin.name(), plugin.version());

        // Register operations
        for op in plugin.operations() {
            debug!("Registering operation: {}", op.name);
            self.operations.insert(op.name, op.handler);
        }

        self.plugins.push(plugin);
    }

    /// Get an operation handler
    pub fn get_operation(&self, name: &str) -> Option<Arc<dyn OperationHandler>> {
        self.operations.get(name).cloned()
    }

    /// List all registered operations
    pub fn list_operations(&self) -> Vec<String> {
        self.operations.keys().cloned().collect()
    }

    /// Get the number of loaded plugins
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Example plugin implementation
pub mod example {
    use super::*;

    pub struct ExamplePlugin {
        name: String,
        version: String,
    }

    impl ExamplePlugin {
        pub fn new() -> Self {
            Self { name: "example-plugin".to_string(), version: "0.1.0".to_string() }
        }
    }

    #[async_trait]
    impl CryptoPlugin for ExamplePlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> &str {
            &self.version
        }

        async fn initialize(&mut self, _context: PluginContext) -> CryptoTEEResult<()> {
            info!("Initializing example plugin");
            Ok(())
        }

        fn operations(&self) -> Vec<Operation> {
            vec![Operation {
                name: "example_operation".to_string(),
                handler: Arc::new(ExampleOperationHandler),
            }]
        }
    }

    struct ExampleOperationHandler;

    #[async_trait]
    impl OperationHandler for ExampleOperationHandler {
        async fn handle(&self, _context: &OperationContext) -> CryptoTEEResult<serde_json::Value> {
            Ok(serde_json::json!({
                "result": "example operation executed"
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_manager() {
        let mut manager = PluginManager::new();
        assert_eq!(manager.plugin_count(), 0);

        // Register example plugin
        let plugin = Box::new(example::ExamplePlugin::new());
        manager.register(plugin);

        assert_eq!(manager.plugin_count(), 1);
        assert!(manager.get_operation("example_operation").is_some());

        let operations = manager.list_operations();
        assert_eq!(operations.len(), 1);
        assert!(operations.contains(&"example_operation".to_string()));
    }
}
