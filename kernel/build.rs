use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Assembly files to compile
    let asm_files = [
        ("src/boot.s", "boot.o"),
        ("src/exception/vectors.s", "vectors.o"),
        ("src/sched/switch.s", "switch.o"),
    ];

    let mut object_files = Vec::new();

    for (src, obj) in &asm_files {
        let obj_path = out_dir.join(obj);

        let status = Command::new("clang")
            .args([
                "--target=aarch64-unknown-none",
                "-c",
                *src,
                "-o",
            ])
            .arg(&obj_path)
            .status()
            .expect(&format!("Failed to assemble {}", src));

        if !status.success() {
            panic!("Assembly of {} failed", src);
        }

        object_files.push(obj_path);
        println!("cargo:rerun-if-changed={}", src);
    }

    // Create static library - try llvm-ar first, fallback to ar
    let ar_cmd = if Command::new("llvm-ar").arg("--version").output().is_ok() {
        "llvm-ar"
    } else {
        "ar"
    };

    let mut ar = Command::new(ar_cmd);
    ar.args(["crs"]).arg(out_dir.join("libboot.a"));
    for obj in &object_files {
        ar.arg(obj);
    }

    let status = ar.status().expect("Failed to run ar");

    if !status.success() {
        panic!("Creating archive failed");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=boot");
}
