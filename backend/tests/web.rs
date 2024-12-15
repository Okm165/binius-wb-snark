//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use binius_web_snark::{run_sha2, run_sha3, Output};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_run_sha2() {
    // Pass input to the `run` function
    let result = run_sha2(serde_wasm_bindgen::to_value("aabbcc").unwrap());

    // Assert successful execution
    assert!(result.is_ok(), "Run function failed: {:?}", result.err());

    // Optionally parse the output and perform further validation
    if let Ok(output) = result {
        let parsed_output: Output = serde_wasm_bindgen::from_value(output).unwrap();
        console_log!("{:?}", parsed_output);
    }
}

#[wasm_bindgen_test]
fn test_run_sha3() {
    // Pass input to the `run` function
    let result = run_sha3(serde_wasm_bindgen::to_value("aabbcc").unwrap());

    // Assert successful execution
    assert!(result.is_ok(), "Run function failed: {:?}", result.err());

    // Optionally parse the output and perform further validation
    if let Ok(output) = result {
        let parsed_output: Output = serde_wasm_bindgen::from_value(output).unwrap();
        console_log!("{:?}", parsed_output);
    }
}
