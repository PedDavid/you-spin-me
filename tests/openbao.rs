//! Against a real OpenBao dev server. Skipped unless these are set:
//!
//! ```sh
//! docker run -d -p 8200:8200 -e BAO_DEV_ROOT_TOKEN_ID=root openbao/openbao:2.4.1
//! YSM_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 YSM_TEST_OPENBAO_ROOT_TOKEN=root cargo test --test openbao
//! ```

use secrecy::SecretString;
use serde_json::{Value, json};

use you_spin_me::crd::OpenBaoTarget;
use you_spin_me::targets::openbao::{Auth, OpenBao};

const POLICY: &str = r#"
path "secret/data/ysm-test/*" {
  capabilities = ["create", "patch"]
}
"#;

struct Env {
    addr: String,
    root: String,
    http: reqwest::Client,
}

impl Env {
    fn from_env() -> Option<Env> {
        Some(Env {
            addr: std::env::var("YSM_TEST_OPENBAO_ADDR").ok()?,
            root: std::env::var("YSM_TEST_OPENBAO_ROOT_TOKEN").ok()?,
            http: reqwest::Client::new(),
        })
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut req = self
            .http
            .request(method, format!("{}/v1/{path}", self.addr))
            .header("X-Vault-Token", token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.unwrap();
        let status = res.status().as_u16();
        let body = res.json().await.unwrap_or(Value::Null);
        (status, body)
    }
}

fn target(path: &str, key: &str) -> OpenBaoTarget {
    OpenBaoTarget {
        mount: "secret".into(),
        path: path.into(),
        key: key.into(),
    }
}

#[tokio::test]
async fn write_only_policy_round_trip() {
    let Some(env) = Env::from_env() else {
        eprintln!("skipping: YSM_TEST_OPENBAO_ADDR / YSM_TEST_OPENBAO_ROOT_TOKEN not set");
        return;
    };
    let (status, _) = env
        .call(
            reqwest::Method::PUT,
            "sys/policies/acl/ysm-write",
            &env.root,
            Some(json!({"policy": POLICY})),
        )
        .await;
    assert!(status < 300, "creating policy: {status}");
    let (status, body) = env
        .call(
            reqwest::Method::POST,
            "auth/token/create",
            &env.root,
            Some(json!({"policies": ["ysm-write"], "no_default_policy": true, "ttl": "10m"})),
        )
        .await;
    assert_eq!(status, 200);
    let limited = body["auth"]["client_token"].as_str().unwrap().to_string();

    let dir = std::env::temp_dir().join(format!("ysm-bao-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_file = dir.join("token");
    std::fs::write(&token_file, &limited).unwrap();
    let bao = OpenBao::new(env.addr.parse().unwrap(), Auth::TokenFile(token_file), None).unwrap();

    let path = format!("ysm-test/{}", std::process::id());
    // New path: PATCH 404s, then POST creates it.
    bao.write_key(&target(&path, "token"), &SecretString::from("first"))
        .await
        .unwrap();
    // Existing path: PATCH adds a second key and keeps the first.
    bao.write_key(&target(&path, "other"), &SecretString::from("second"))
        .await
        .unwrap();
    // And replaces an existing key.
    bao.write_key(&target(&path, "token"), &SecretString::from("third"))
        .await
        .unwrap();

    let (status, body) = env
        .call(
            reqwest::Method::GET,
            &format!("secret/data/{path}"),
            &env.root,
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["data"]["data"],
        json!({"token": "third", "other": "second"})
    );

    // The app's token cannot read back what it wrote, nor its metadata.
    for read_path in [
        format!("secret/data/{path}"),
        format!("secret/metadata/{path}"),
    ] {
        let (status, _) = env
            .call(reqwest::Method::GET, &read_path, &limited, None)
            .await;
        assert_eq!(status, 403, "reading {read_path} must be denied");
    }

    // Paths outside the policy are rejected, with OpenBao's message.
    let err = bao
        .write_key(&target("elsewhere/x", "token"), &SecretString::from("nope"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("403"), "{err}");
    assert!(!err.contains("nope"));
}
