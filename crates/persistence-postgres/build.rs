fn main() {
    // `embed_migrations!` reads outside this package. Cargo does not reliably
    // discover newly added migration directories from the proc-macro expansion,
    // so make the directory an explicit build input for incremental/container builds.
    println!("cargo:rerun-if-changed=../../migrations");
}
