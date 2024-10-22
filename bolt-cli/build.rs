// Perform the code generation for the protobuf files.
fn main() -> std::io::Result<()> {
    let mut proto_build = prost_build::Config::new();

    proto_build.out_dir("src/pb");
    proto_build.compile_protos(&["proto/eth2-signer-api/lister.proto"], &["proto/eth2-signer-api"])
}
