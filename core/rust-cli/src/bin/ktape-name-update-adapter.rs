use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = (|| -> Result<(), String> {
        if args.len() != 2 {
            return Err("RELEASE_ADAPTER_ARGUMENTS_INVALID".into());
        }
        let response = ktapeout_cli::release_native_adapter::run(Path::new(&args[0]))?;
        let bytes = serde_json::to_vec(&response).map_err(|_| "RELEASE_ADAPTER_JSON_INVALID")?;
        std::fs::write(Path::new(&args[1]), bytes)
            .map_err(|_| "RELEASE_ADAPTER_RESPONSE_WRITE_FAILED".to_string())
    })();
    if let Err(code) = result {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
