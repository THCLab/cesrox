use std::process::{Command, Output};

const LEGACY_KEL: &[u8] = include_bytes!("../../cesr/tests/data/legacy_kel.cesr");

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cesr-migrate"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn converts_files_and_reports_status() {
    let dir = std::env::temp_dir().join(format!("cesr-migrate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("kel.cesr");
    let output = dir.join("kel-v2.cesr");
    std::fs::write(&input, LEGACY_KEL).unwrap();

    let check = run(&["--check", input.to_str().unwrap()]);
    assert_eq!(check.status.code(), Some(1));

    let converted = run(&[input.to_str().unwrap(), "-o", output.to_str().unwrap()]);
    assert!(converted.status.success());
    let v2 = std::fs::read(&output).unwrap();
    assert!(cesrox::parse_with(&v2, cesrox::Counting::Quadlets).is_ok());

    let again = run(&["--check", output.to_str().unwrap()]);
    assert_eq!(again.status.code(), Some(0));

    let broken = dir.join("broken.cesr");
    std::fs::write(&broken, b"-KABnot-cesr").unwrap();
    let failed = run(&[broken.to_str().unwrap()]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&failed.stderr).starts_with("Error:"));

    std::fs::remove_dir_all(dir).unwrap();
}
