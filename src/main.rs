use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("shuttle=info".parse()?),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|a| a == "--rpc") {
        eprintln!("shuttle must be launched by Omegon with --rpc");
        std::process::exit(1);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let ext = shuttle::extension::ShuttleExtension::new();
            omegon_extension::serve_v2(ext).await?;
            Ok(())
        })
}
