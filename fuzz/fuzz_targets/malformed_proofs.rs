#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs_fuzz::{check_untrusted, malformed_proof};

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let proof = malformed_proof(input)?;
    check_untrusted(input, &proof)
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
