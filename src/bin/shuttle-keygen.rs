use ed25519_dalek::SigningKey;
use styrene_identity::derive::KeyDeriver;
use styrene_identity::file_signer::FileSigner;
use styrene_identity::signer::IdentitySigner;
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: shuttle-keygen <identity-path> <label>");
        eprintln!("  If the identity file does not exist, it is created.");
        eprintln!("  Reads STYRENE_PASSPHRASE from env (default: empty).");
        eprintln!("  Outputs OpenSSH authorized_keys line to stdout.");
        std::process::exit(1);
    }

    let identity_path = &args[1];
    let label = &args[2];

    let passphrase = std::env::var("STYRENE_PASSPHRASE")
        .unwrap_or_default()
        .into_bytes();

    let signer = FileSigner::with_static_passphrase(identity_path, &passphrase);

    if !std::path::Path::new(identity_path).exists() {
        signer.generate(&passphrase).unwrap_or_else(|e| {
            eprintln!("failed to generate identity: {e}");
            std::process::exit(1);
        });
        eprintln!("created identity: {identity_path}");
    }

    let root = signer.root_secret().await.unwrap_or_else(|e| {
        eprintln!("failed to unlock identity: {e}");
        std::process::exit(1);
    });

    let deriver = KeyDeriver::new(root.as_bytes());
    let mut seed = deriver.derive_ssh_user_key(label).unwrap_or_else(|e| {
        eprintln!("failed to derive key for label '{label}': {e}");
        std::process::exit(1);
    });

    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();

    // SSH wire format blob: string "ssh-ed25519" + bytes pubkey
    let algo = b"ssh-ed25519";
    let mut blob = Vec::new();
    blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    blob.extend_from_slice(algo);
    blob.extend_from_slice(&(pubkey_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(&pubkey_bytes);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    println!("ssh-ed25519 {b64} shuttle-{label}");
}
