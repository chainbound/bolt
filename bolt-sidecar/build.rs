fn main() {
    // Built uses the `MANIFEST_DIR` environment variable to find the location of `Cargo.toml` and
    // `.git`. When building from PWD=$BOLT_REPO/bolt-sidecar, the `.git` directory won't be
    // found, therefore the git commit info will be missing from the build-time information.
    //
    // To work around this, we also attempt to read the commit hash from the `.git/FETCH_HEAD` file
    // and make it available as an environment variable at runtime.

    // make the commit hash available as an environment variable at runtime
    if let Ok(commit_hash) = std::fs::read_to_string("../.git/FETCH_HEAD") {
        println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash.trim());
    }

    built::write_built_file().expect("Failed to acquire build-time information");
}
