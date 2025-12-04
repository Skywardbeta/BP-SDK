use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = PathBuf::from(&manifest_dir);
    let ion_path = manifest_path.parent().unwrap().parent().unwrap();
    
    // Link ION-DTN libraries
    println!("cargo:rustc-link-search=native={}/lib", ion_path.display());
    println!("cargo:rustc-link-lib=bp");
    println!("cargo:rustc-link-lib=ion");
    println!("cargo:rustc-link-lib=ici");
    
    // Include paths for ION headers
    let ion_include = ion_path.join("bpv7/include");
    let ici_include = ion_path.join("ici/include");
    
    println!("cargo:include={}", ion_include.display());
    println!("cargo:include={}", ici_include.display());
    
    // Rerun if ION headers change
    println!("cargo:rerun-if-changed={}", ion_include.display());
    println!("cargo:rerun-if-changed={}", ici_include.display());
} 