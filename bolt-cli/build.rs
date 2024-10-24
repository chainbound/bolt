use std::{fs, io, path::Path};

const PB_OUT_DIR: &str = "src/pb";

// Perform the code generation for the protobuf files.
fn main() -> io::Result<()> {
    // create the /src/pb directory if it doesn't exist
    if !Path::new(PB_OUT_DIR).exists() {
        fs::create_dir(PB_OUT_DIR)?;
    }

    tonic_build::configure().build_client(true).out_dir(PB_OUT_DIR).compile_protos(
        &[
            "proto/eth2-signer-api/v1/lister.proto",
            "proto/eth2-signer-api/v1/signer.proto",
            "proto/eth2-signer-api/v1/accountmanager.proto",
            "proto/eth2-signer-api/v1/walletmanager.proto",
        ],
        &["proto/eth2-signer-api/v1/", "proto/eth2-signer-api/"],
    )
}
