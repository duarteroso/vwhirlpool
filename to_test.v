module vwhirlpool

import math

//
fn test_to8() {
	assert to_u8(math.max_u64) == math.max_u8
	assert to_u8(-math.max_u64) == 1
}

//
fn test_to16() {
	assert to_u16(math.max_u64) == math.max_u16
	assert to_u16(-math.max_u64) == 1
}

//
fn test_to32() {
	assert to_u32(math.max_u64) == math.max_u32
	assert to_u32(-math.max_u64) == 1
}

//
fn test_to64() {
	assert to_u64(math.max_u64) == math.max_u64
	assert to_u64(-math.max_u64) == 1
}
