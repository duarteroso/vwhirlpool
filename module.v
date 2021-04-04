module vwhirlpool

import duarteroso.vsemver

// Module init
fn init() {
}

// Module semver
pub fn module_version() vsemver.SemVer {
	return vsemver.SemVer {
		major: 1
		minor: 0
		patch: 0
	}
}

// Hashing function
pub fn hash(input string) string {
	// Initialize Nessie struct
	mut n := create_nessie()
	// Add input string
	n.add(input.bytes())
	// Create digest
	digest := n.finalize()
	// Translate digest into string
	mut h := byte_array_to_string(digest)
	// Hash ready
	return h
}

fn byte_array_to_string(ba []byte) string {
	mut s := ''
	for i in 0 .. ba.len {
		s += '${ba[i]:02x}'.to_upper()
	}
	return s
}
