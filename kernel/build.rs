use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Compile boot.s
    let status = Command::new("clang")
        .args([
            "--target=aarch64-unknown-none",
            "-c",
            "src/boot.s",
            "-o",
        ])
        .arg(out_dir.join("boot.o"))
        .status()
        .expect("Failed to run assembler");

    if !status.success() {
        panic!("Assembly failed");
    }

    // Create static library - try llvm-ar first, fallback to ar
    let ar_cmd = if Command::new("llvm-ar").arg("--version").output().is_ok() {
        "llvm-ar"
    } else {
        "ar"
    };

    let status = Command::new(ar_cmd)
        .args(["crs"])
        .arg(out_dir.join("libboot.a"))
        .arg(out_dir.join("boot.o"))
        .status()
        .expect("Failed to run ar");

    if !status.success() {
        panic!("Creating archive failed");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=boot");
    println!("cargo:rerun-if-changed=src/boot.s");
}
