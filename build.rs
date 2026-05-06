fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Jito block-engine protos — `shredstream.proto` imports `shared.proto`
    // by name, so the include path is `protos/`.
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "protos/auth.proto",
                "protos/shared.proto",
                "protos/shredstream.proto",
            ],
            &["protos"],
        )?;
    // Yellowstone protos — `geyser.proto` imports `solana-storage.proto`
    // by name. Compiled as a separate invocation with its own include
    // path so protoc doesn't register `solana-storage.proto` twice
    // (once as `solana-storage.proto`, once as `yellowstone/solana-storage.proto`).
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "protos/yellowstone/geyser.proto",
                "protos/yellowstone/solana-storage.proto",
            ],
            &["protos/yellowstone"],
        )?;
    println!("cargo:rerun-if-changed=protos/auth.proto");
    println!("cargo:rerun-if-changed=protos/shared.proto");
    println!("cargo:rerun-if-changed=protos/shredstream.proto");
    println!("cargo:rerun-if-changed=protos/yellowstone/geyser.proto");
    println!("cargo:rerun-if-changed=protos/yellowstone/solana-storage.proto");
    Ok(())
}
