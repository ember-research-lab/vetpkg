pub mod advisory;
pub mod dependency;
pub mod fresh;
pub mod hook;
pub mod maintainer;
pub mod popularity;
pub mod publish_anomaly;
pub mod typosquat;

use crate::types::{PackageIntel, PolicyConfig, Signal};

pub trait Check {
    fn name(&self) -> &'static str;
    fn evaluate(&self, intel: &PackageIntel, config: &PolicyConfig) -> Vec<Signal>;
}
