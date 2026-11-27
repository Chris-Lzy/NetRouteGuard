use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=app.ico");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let res_path = out_dir.join("app.res");
    let status = Command::new("windres")
        .args(["app.rc", "-O", "coff", "-o"])
        .arg(&res_path)
        .status()
        .expect("Failed to run windres");
    assert!(status.success(), "windres failed");
    println!("cargo:rustc-link-arg={}", res_path.display());
}
