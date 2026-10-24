// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_identity_sidecar::{capabilities, config::Config};
fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("capabilities") => {
            println!("{}", serde_json::to_string_pretty(&capabilities()).unwrap())
        }
        Some("check-config") | Some("check-serving-config") => {
            let serving = std::env::args().nth(1).as_deref() == Some("check-serving-config");
            let result = args
                .next()
                .ok_or_else(|| "missing_config_path".to_string())
                .and_then(|path| {
                    std::fs::read_to_string(path).map_err(|_| "config_read_failed".to_string())
                })
                .and_then(|text| {
                    serde_json::from_str::<Config>(&text)
                        .map_err(|_| "invalid_config_json".to_string())
                })
                .and_then(|config| {
                    if serving { config.validate_serving() } else { config.validate() }.map_err(|e| e.to_string())
                });
            match result {
                Ok(()) => println!("config_valid"),
                Err(code) => {
                    eprintln!("{code}");
                    std::process::exit(2);
                }
            }
        }
        Some("serve") => {
            let path = args.next().ok_or_else(|| "missing_config_path".to_string());
            let result = path
                .and_then(|path| {
                    std::fs::read_to_string(path).map_err(|_| "config_read_failed".to_string())
                })
                .and_then(|text| {
                    serde_json::from_str::<Config>(&text)
                        .map_err(|_| "invalid_config_json".to_string())
                });
            match result {
                Ok(config) => {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    if let Err(code) = runtime.block_on(oan_identity_sidecar::server::serve(config))
                    {
                        eprintln!("{code}");
                        std::process::exit(2);
                    }
                }
                Err(code) => {
                    eprintln!("{code}");
                    std::process::exit(2);
                }
            }
        }
        _ => println!(
            "Usage: oan-identity-sidecar capabilities | check-config <path> | check-serving-config <path> | serve <path>"
        ),
    }
}
