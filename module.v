module vwhirlpool

import v.vmod

// manifest of module
pub fn manifest() !vmod.Manifest {
	return vmod.decode(@VMOD_FILE) or { err }
}

// hash function
pub fn hash(input string) string {
	// Initialize Nessie struct
	mut n := create_nessie()
	// Add input string
	n.add(input.bytes())
	// Create digest
	digest := n.finalize()
	// Translate digest into string
	h := byte_array_to_string(digest)
	// Hash ready
	return h
}

// byte_array_to_string tranform byte array into human readable string
fn byte_array_to_string(ba []u8) string {
	mut s := ''
	for i in 0 .. ba.len {
		s += '${ba[i]:02x}'.to_upper()
	}
	return s
}
