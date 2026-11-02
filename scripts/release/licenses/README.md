# Reviewed missing-license supplements

Some locked crate archives omit their workspace license files. overrides.json
maps exact crate name/version pairs to local texts, source URLs and SHA-256.
Texts were fetched from the source commits in the crates' .cargo_vcs_info.json;
HPKE declares MPL-2.0 but that upstream tree supplies no MPL text, so its text
comes from Mozilla's MPL 2.0 publication, with trailing whitespace normalized. Exact crate source URLs are included
in THIRD_PARTY_NOTICES, including the unmodified MPL dependencies.

The build uses compiler-artifact package IDs and Cargo metadata from Cargo.lock.
It includes packaged license/copyright/notice files recursively, including
SQLCipher, OpenSSL, ring/BoringSSL and nested vendored notices. Overrides apply
only to missing texts and are version-bound, with hashes checked at build time.
New dependency versions or unknown license identifiers fail for review rather
than silently reusing a missing-license exception. No build-time network fetch
of license texts occurs.
