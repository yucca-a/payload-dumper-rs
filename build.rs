fn main() {
    prost_build::compile_protos(
        &["proto/update_metadata.proto"],
        &["proto/"],
    )
    .expect("Failed to compile protobuf");
}
