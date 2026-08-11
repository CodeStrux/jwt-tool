use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand, ValueEnum};
use colored::{control, Colorize};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "jwt-tool",
    about = "Inspect and validate JWTs",
    version,
    author = "CodeStrux Tech <aao@codestrux.tech>",
    after_help = "CodeStrux Tech - https://codestrux.tech"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decode a JWT and print its header and payload
    Decode {
        /// Token source: "-" reads the token from stdin
        input: String,

        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Verify a JWT's signature
    Verify {
        /// Token source: "-" reads the token from stdin
        input: String,

        /// Algorithm the token is expected to be signed with
        #[arg(long, value_enum)]
        alg: SigAlg,

        /// Shared secret, for HMAC algorithms (HS256/HS384/HS512)
        #[arg(long, conflicts_with = "public_key")]
        secret: Option<String>,

        /// Path to a PEM-encoded public key, for RSA/EC/EdDSA algorithms
        #[arg(long, conflicts_with = "secret")]
        public_key: Option<PathBuf>,

        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SigAlg {
    #[value(name = "HS256")]
    Hs256,
    #[value(name = "HS384")]
    Hs384,
    #[value(name = "HS512")]
    Hs512,
    #[value(name = "RS256")]
    Rs256,
    #[value(name = "RS384")]
    Rs384,
    #[value(name = "RS512")]
    Rs512,
    #[value(name = "ES256")]
    Es256,
    #[value(name = "ES384")]
    Es384,
    #[value(name = "PS256")]
    Ps256,
    #[value(name = "PS384")]
    Ps384,
    #[value(name = "PS512")]
    Ps512,
    #[value(name = "EdDSA")]
    EdDsa,
}

enum KeyKind {
    Hmac,
    Rsa,
    Ec,
    Ed,
}

impl SigAlg {
    fn as_str(self) -> &'static str {
        match self {
            SigAlg::Hs256 => "HS256",
            SigAlg::Hs384 => "HS384",
            SigAlg::Hs512 => "HS512",
            SigAlg::Rs256 => "RS256",
            SigAlg::Rs384 => "RS384",
            SigAlg::Rs512 => "RS512",
            SigAlg::Es256 => "ES256",
            SigAlg::Es384 => "ES384",
            SigAlg::Ps256 => "PS256",
            SigAlg::Ps384 => "PS384",
            SigAlg::Ps512 => "PS512",
            SigAlg::EdDsa => "EdDSA",
        }
    }

    fn to_jwt_alg(self) -> Algorithm {
        match self {
            SigAlg::Hs256 => Algorithm::HS256,
            SigAlg::Hs384 => Algorithm::HS384,
            SigAlg::Hs512 => Algorithm::HS512,
            SigAlg::Rs256 => Algorithm::RS256,
            SigAlg::Rs384 => Algorithm::RS384,
            SigAlg::Rs512 => Algorithm::RS512,
            SigAlg::Es256 => Algorithm::ES256,
            SigAlg::Es384 => Algorithm::ES384,
            SigAlg::Ps256 => Algorithm::PS256,
            SigAlg::Ps384 => Algorithm::PS384,
            SigAlg::Ps512 => Algorithm::PS512,
            SigAlg::EdDsa => Algorithm::EdDSA,
        }
    }

    fn key_kind(self) -> KeyKind {
        match self {
            SigAlg::Hs256 | SigAlg::Hs384 | SigAlg::Hs512 => KeyKind::Hmac,
            SigAlg::Rs256 | SigAlg::Rs384 | SigAlg::Rs512 | SigAlg::Ps256 | SigAlg::Ps384 | SigAlg::Ps512 => {
                KeyKind::Rsa
            }
            SigAlg::Es256 | SigAlg::Es384 => KeyKind::Ec,
            SigAlg::EdDsa => KeyKind::Ed,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Decode { input, format } => decode(&input, format).map(|_| true),
        Command::Verify {
            input,
            alg,
            secret,
            public_key,
            format,
        } => verify(&input, alg, secret, public_key, format),
    };

    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("{} {err}", "error:".red().bold());
            ExitCode::FAILURE
        }
    }
}

/// JSON output must stay machine-parseable, so colors are only ever applied
/// to the human-facing text format, and are forced off otherwise.
fn apply_color_mode(format: OutputFormat) {
    if format == OutputFormat::Json {
        control::set_override(false);
    }
}

fn decode(input: &str, format: OutputFormat) -> Result<(), String> {
    apply_color_mode(format);
    let token = read_token(input)?;
    let (header, payload, signature_b64) = decode_parts(&token)?;

    match format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "header": header,
                "payload": payload,
                "signature": signature_b64,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        OutputFormat::Text => {
            println!("{}", "Header".bold().cyan());
            println!("{}", serde_json::to_string_pretty(&header).unwrap());
            println!();
            println!("{}", "Payload".bold().cyan());
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
            println!();
            println!(
                "{} {}",
                "Signature (base64url):".bold().cyan(),
                signature_b64
            );
        }
    }

    Ok(())
}

/// Returns whether the signature was found valid, so `main` can pick an exit code.
fn verify(
    input: &str,
    alg: SigAlg,
    secret: Option<String>,
    public_key: Option<PathBuf>,
    format: OutputFormat,
) -> Result<bool, String> {
    apply_color_mode(format);
    let token = read_token(input)?;
    let (header, payload, signature_b64) = decode_parts(&token)?;

    let decoding_key = load_decoding_key(alg, secret.as_deref(), public_key.as_ref())?;

    // The expected algorithm is supplied explicitly by the caller (not read from the
    // token's own header) so a forged token can't downgrade itself to a weaker or
    // unintended algorithm (e.g. the classic RS256 -> HS256 confusion attack).
    let mut validation = Validation::new(alg.to_jwt_alg());
    // Signature validity is independent of claim freshness; claims like `exp`/`nbf`
    // are a separate concern from whether the signature itself checks out.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let verify_result = jsonwebtoken::decode::<Value>(&token, &decoding_key, &validation);
    let (is_valid, error_message) = match &verify_result {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    match format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "header": header,
                "payload": payload,
                "signature": signature_b64,
                "algorithm": alg.as_str(),
                "valid": is_valid,
                "error": error_message,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        OutputFormat::Text => {
            println!("{}", "Header".bold().cyan());
            println!("{}", serde_json::to_string_pretty(&header).unwrap());
            println!();
            println!("{}", "Payload".bold().cyan());
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
            println!();
            println!(
                "{} {}",
                "Signature (base64url):".bold().cyan(),
                signature_b64
            );
            println!();
            println!("{} {}", "Algorithm:".bold().cyan(), alg.as_str());
            let status = if is_valid {
                "true".green().bold()
            } else {
                "false".red().bold()
            };
            println!("{} {}", "Signature valid:".bold().cyan(), status);
            if let Some(msg) = &error_message {
                println!("{} {}", "Reason:".bold().red(), msg.red());
            }
        }
    }

    Ok(is_valid)
}

fn read_token(input: &str) -> Result<String, String> {
    if input != "-" {
        return Err(format!(
            "unsupported input source '{input}', expected '-' to read from stdin"
        ));
    }

    let mut token = String::new();
    io::stdin()
        .read_to_string(&mut token)
        .map_err(|e| format!("failed to read token from stdin: {e}"))?;
    Ok(token.trim().to_string())
}

fn decode_parts(token: &str) -> Result<(Value, Value, String), String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "malformed JWT: expected 3 dot-separated parts, found {}",
            parts.len()
        ));
    }

    let header = decode_json_segment("header", parts[0])?;
    let payload = decode_json_segment("payload", parts[1])?;
    Ok((header, payload, parts[2].to_string()))
}

fn decode_json_segment(name: &str, segment: &str) -> Result<Value, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("failed to base64url-decode {name}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("failed to parse {name} as JSON: {e}"))
}

fn load_decoding_key(
    alg: SigAlg,
    secret: Option<&str>,
    public_key: Option<&PathBuf>,
) -> Result<DecodingKey, String> {
    match alg.key_kind() {
        KeyKind::Hmac => {
            let secret = secret
                .ok_or_else(|| format!("algorithm {} requires --secret", alg.as_str()))?;
            Ok(DecodingKey::from_secret(secret.as_bytes()))
        }
        kind @ (KeyKind::Rsa | KeyKind::Ec | KeyKind::Ed) => {
            let path = public_key.ok_or_else(|| {
                format!("algorithm {} requires --public-key <PEM file>", alg.as_str())
            })?;
            let pem = std::fs::read(path)
                .map_err(|e| format!("failed to read public key file '{}': {e}", path.display()))?;
            match kind {
                KeyKind::Rsa => DecodingKey::from_rsa_pem(&pem),
                KeyKind::Ec => DecodingKey::from_ec_pem(&pem),
                KeyKind::Ed => DecodingKey::from_ed_pem(&pem),
                KeyKind::Hmac => unreachable!(),
            }
            .map_err(|e| format!("failed to load public key: {e}"))
        }
    }
}
