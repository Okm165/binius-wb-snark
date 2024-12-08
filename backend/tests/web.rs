//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use std::println;

use binius_keccak::run;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_run() {
    // Format output as JSON
    let output_values: Vec<String> = (0..25).into_iter().map(|f| f.to_string()).collect();

    // Pass input to the `run` function
    let result = run(serde_wasm_bindgen::to_value(&output_values).unwrap());

    // Assert successful execution
    assert!(result.is_ok(), "Run function failed: {:?}", result.err());

    // Optionally parse the output and perform further validation
    if let Ok(output) = result {
        let parsed_output: Vec<String> = serde_wasm_bindgen::from_value(output).unwrap();
        println!("{:?}", parsed_output);
    }
}
