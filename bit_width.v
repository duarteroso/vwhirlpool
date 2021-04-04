module vwhirlpool

//
pub fn to_u8(x u64) u16 {
	return u16(byte(x & 0xff))
}

//
pub fn to_u16(x u64) u16 {
	return u16(x & 0xffff)
}

//
pub fn to_u32(x u64) u32 {
	return u32(x & 0xffffffff)
}

//
pub fn to_u64(x u64) u64 {
	return u64(x & 0xffffffffffffffff)
}
