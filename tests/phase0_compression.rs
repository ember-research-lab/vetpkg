//! End-to-end gzip+tar fixture extraction (Phase 0 success criterion #8).
//!
//! All fixtures are constructed in-process via the system `gzip` binary.
//! No network, no untrusted archive formats. Skipped if `gzip` is absent.

use std::io::Write;
use std::process::{Command, Stdio};

use vetpkg::archive::tar;
use vetpkg::compress::gzip;
use vetpkg::platform::TempDir;

fn has_gzip() -> bool {
    Command::new("gzip")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut child = Command::new("gzip")
        .arg("-c")
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn gzip");
    child.stdin.as_mut().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().expect("gzip output");
    assert!(out.status.success(), "gzip failed");
    out.stdout
}

#[test]
fn round_trip_gzip_of_tar_with_pax_longname() {
    if !has_gzip() {
        eprintln!("skipping: gzip not on PATH");
        return;
    }

    let long_name = "package/very-long-subdirectory-name-forcing-pax/inner/file-with-a-lengthy-filename-exceeding-100-bytes-to-trigger-the-pax-long-name-path-record-handling.txt";
    assert!(long_name.len() > 100);

    let entries: Vec<(&str, &[u8])> = vec![
        (
            "package/package.json",
            b"{\"name\":\"tiny\",\"version\":\"1.0.0\"}",
        ),
        (
            "package/index.js",
            b"module.exports = function () { return 42; };\n",
        ),
        (long_name, b"content inside the deeply-nested file"),
    ];
    let tar_bytes = tar::build_tar_pax(&entries);
    let gz = gzip_bytes(&tar_bytes);

    let decoded = gzip::gunzip(&gz).expect("gunzip");
    assert_eq!(decoded, tar_bytes);

    let td = TempDir::new("vetpkg-phase0-e2e").unwrap();
    let extracted = tar::extract_tar(&decoded, td.path()).expect("extract");
    assert_eq!(extracted.len(), 3);

    let json_body = std::fs::read(td.path().join("package/package.json")).unwrap();
    assert_eq!(&json_body, b"{\"name\":\"tiny\",\"version\":\"1.0.0\"}");

    let long_body = std::fs::read(td.path().join(long_name)).unwrap();
    assert_eq!(&long_body, b"content inside the deeply-nested file");
}

#[test]
fn large_compressed_payload_decompresses() {
    if !has_gzip() {
        eprintln!("skipping: gzip not on PATH");
        return;
    }
    let chunk = b"vetpkg bulk test payload repetition ";
    let mut data = Vec::with_capacity(256 * 1024);
    while data.len() < 256 * 1024 {
        data.extend_from_slice(chunk);
    }
    let gz = gzip_bytes(&data);
    let decoded = gzip::gunzip(&gz).expect("gunzip");
    assert_eq!(decoded, data);
}
