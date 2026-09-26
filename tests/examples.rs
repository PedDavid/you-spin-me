//! Every example `ApiKey` in `deploy/examples` must deserialize.

use you_spin_me::crd::ApiKey;

#[test]
fn examples_deserialize() {
    let mut count = 0;
    for entry in std::fs::read_dir("deploy/examples").unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("apikey-") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let key: ApiKey = serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!key.name().is_empty(), "{name}");
        count += 1;
    }
    assert!(count > 0);
}
