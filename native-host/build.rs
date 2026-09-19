use std::path::Path;

fn main() {
    const FRONTEND_DIST: &str = "../frontend/dist";
    const FRONTEND_INDEX: &str = "../frontend/dist/index.html";

    // rust-embed reads these files during compilation, but Cargo does not know
    // that changes under frontend/dist must invalidate the host binary.
    println!("cargo:rerun-if-changed={FRONTEND_DIST}");

    if !Path::new(FRONTEND_INDEX).is_file() {
        panic!(
            "frontend build is missing: run `npm run build --prefix frontend` before building native-host"
        );
    }
}
