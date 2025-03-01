// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
// Skip ARM(cross-compile) until I figure out how to run ctest on this.
#![cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
// Skip code coverage.
#![cfg(not(tarpaulin))]

use std::env;
use std::path::Path;
use std::process::Command;

#[test]
fn run_ctest() {
    // Run iot-hsm-c tests
    println!("Start Running ctest for HSM library");
    let build_dir =
        Path::new(&env::var("OUT_DIR").expect("Did not find OUT_DIR in build environment"))
            .join("build");
    let test_output = Command::new("ctest")
        .arg("-C")
        .arg("Release")
        .arg("-VV")
        .arg(format!("-j {}", num_cpus::get()))
        .current_dir(build_dir)
        .output()
        .expect("failed to execute ctest");
    println!("status: {}", test_output.status);
    println!("stdout: {}", String::from_utf8_lossy(&test_output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&test_output.stderr));
    assert!(test_output.status.success(), "Running CTest failed.");
    println!("Done Running ctest for HSM library");
}
