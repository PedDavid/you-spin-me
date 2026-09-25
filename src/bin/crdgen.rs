//! Prints the `ApiKey` CustomResourceDefinition as YAML.

use kube::CustomResourceExt;
use you_spin_me::crd::ApiKey;

fn main() -> anyhow::Result<()> {
    print!("{}", serde_yaml::to_string(&ApiKey::crd())?);
    Ok(())
}
