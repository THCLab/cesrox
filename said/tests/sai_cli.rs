//! The `sai` command line tool.
#![cfg(feature = "file")]

use std::process::Command;

fn sai(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sai"))
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

fn generated(args: &[&str]) -> String {
    let (ok, text) = sai(args);
    assert!(ok, "{text}");
    text.trim().rsplit(' ').next().unwrap().to_string()
}

#[test]
fn data_and_file_give_the_same_sai() {
    let path = std::env::temp_dir().join(format!("sai-cli-{}.txt", std::process::id()));
    std::fs::write(&path, "hello").unwrap();
    for code in ["E", "F", "G", "H", "I", "0D", "0E", "0F", "0G"] {
        let from_data = generated(&["gen", "-d", "hello", "-t", code]);
        let from_file = generated(&["gen", "-f", path.to_str().unwrap(), "-t", code]);
        assert_eq!(from_data, from_file, "{code}");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn verify_checks_the_data() {
    let sai_text = generated(&["gen", "-d", "hello", "-t", "E"]);
    assert!(sai(&["verify", "-s", &sai_text, "-d", "hello"]).0);
    assert!(!sai(&["verify", "-s", &sai_text, "-d", "hello!"]).0);
}

#[test]
fn bad_input_is_an_error_not_a_crash() {
    for args in [
        &["gen", "-d", "x", "-t", "X"][..],
        &["verify", "-s", "0", "-d", "x"],
        &["gen", "-f", "/nonexistent/file", "-t", "E"],
    ] {
        let (ok, text) = sai(args);
        assert!(!ok);
        assert!(text.starts_with("Error:"), "{text}");
    }
}
