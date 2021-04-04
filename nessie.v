module vwhirlpool

//
const (
	digest_bytes = 64
	digest_bits  = (8 * digest_bytes)
	wblock_bytes = 64
	wblock_bits  = (8 * wblock_bytes)
	length_bytes = 32
	length_bits  = (8 * length_bytes)
)

//
struct Nessie {
mut:
	bit_length  []byte
	buffer      []byte
	buffer_bits int
	buffer_pos  int
	hash        []u64
}

//
fn create_nessie() &Nessie {
	mut n := &Nessie{}
	n.init()
	return n
}

//
fn (mut n Nessie) init() {
	n.bit_length = []byte{len: vwhirlpool.length_bytes, init: byte(0)}
	n.buffer = []byte{len: vwhirlpool.wblock_bytes, init: byte(0)}
	n.buffer_bits = 0
	n.buffer_pos = 0
	n.hash = []u64{len: vwhirlpool.digest_bytes / 8, init: u64(0)}
}

//
fn (mut n Nessie) add(src []byte) {
	mut source_bits := src.len * 8
	mut source_pos := 0
	mut source_gap := (8 - (int(source_bits) & 7)) & 7
	mut buffer_rem := (n.buffer_bits & 7)
	mut b := u32(0)
	mut carry := u32(0)
	mut buffer_bits := n.buffer_bits
	mut buffer_pos := n.buffer_pos
	//
	mut value := source_bits
	carry = 0
	for i := 31; i >= 0 && (carry != 0 || value != u64(0)); i-- {
		carry += n.bit_length[i] + (u32(value) & 0xff)
		n.bit_length[i] = byte(carry)
		carry >>= 8
		value >>= 8
	}
	//
	for source_bits > 8 {
		b = ((src[source_pos] << source_gap) & 0xff) | ((src[source_pos + 1] & 0xff) >> (8 - source_gap))
		//
		n.buffer[buffer_pos] |= byte(b >> buffer_rem)
		buffer_pos++
		buffer_bits += 8 - buffer_rem
		if buffer_bits == vwhirlpool.digest_bits {
			n.process()
			buffer_bits = 0
			buffer_pos = 0
		}
		n.buffer[buffer_pos] = byte(b << (8 - buffer_rem))
		buffer_bits += buffer_rem
		//
		source_bits -= 8
		source_pos++
	}
	//
	if source_bits > 0 {
		b = (src[source_pos] << source_gap) & 0xff
		n.buffer[buffer_pos] |= byte(b >> buffer_rem)
	} else {
		b = 0
	}
	if buffer_rem + source_bits < 8 {
		buffer_bits += source_bits
	} else {
		buffer_pos++
		buffer_bits += (8 - buffer_rem)
		source_bits -= (8 - buffer_rem)
		if buffer_bits == vwhirlpool.digest_bits {
			n.process()
			buffer_bits = 0
			buffer_pos = 0
		}
		n.buffer[buffer_pos] = byte(b << (8 - buffer_rem))
		buffer_bits += int(source_bits)
	}
	//
	n.buffer_bits = buffer_bits
	n.buffer_pos = buffer_pos
}

//
fn (mut n Nessie) process() {
	mut k := []u64{len: 8, init: 0}
	mut block := []u64{len: 8, init: 0}
	mut state := []u64{len: 8, init: 0}
	mut l := []u64{len: 8, init: 0}
	//
	n.print_derived()
	// TODO: Use to_u8?
	mut offset := 0
	for i := 0; i < 8; i++ {
		block[i] = (u64(n.buffer[offset + 0]) << 56) ^ ((u64(n.buffer[offset + 1]) & u64(0xff)) << 48) ^ ((u64(n.buffer[
			offset + 2]) & u64(0xff)) << 40) ^ ((u64(n.buffer[offset + 3]) & u64(0xff)) << 32) ^ ((u64(n.buffer[
			offset + 4]) & u64(0xff)) << 24) ^ ((u64(n.buffer[offset + 5]) & u64(0xff)) << 16) ^ ((u64(n.buffer[
			offset + 6]) & u64(0xff)) << 8) ^ (u64(n.buffer[offset + 7]) & u64(0xff))
		offset += 8
	}
	//
	for i := 0; i < 8; i++ {
		k[i] = n.hash[i]
		state[i] = block[i] ^ k[i]
	}
	//
	n.intermediate_values(k, state)
	//
	c0 := get_c0()
	c1 := get_c1()
	c2 := get_c2()
	c3 := get_c3()
	c4 := get_c4()
	c5 := get_c5()
	c6 := get_c6()
	c7 := get_c7()
	rc := get_rc()
	for r := 1; r <= 10; r++ {
		l[0] = c0[int(k[0] >> 56)] ^ c1[int(k[7] >> 48) & 0xff] ^ c2[int(k[6] >> 40) & 0xff] ^ c3[int(k[5] >> 32) & 0xff] ^ c4[int(k[4] >> 24) & 0xff] ^ c5[int(k[3] >> 16) & 0xff] ^ c6[int(k[2] >> 8) & 0xff] ^ c7[int(k[1]) & 0xff] ^ rc[r]
		//
		l[1] = c0[int(k[1] >> 56)] ^ c1[int(k[0] >> 48) & 0xff] ^ c2[int(k[7] >> 40) & 0xff] ^ c3[int(k[6] >> 32) & 0xff] ^ c4[int(k[5] >> 24) & 0xff] ^ c5[int(k[4] >> 16) & 0xff] ^ c6[int(k[3] >> 8) & 0xff] ^ c7[int(k[2]) & 0xff]
		//
		l[2] = c0[int(k[2] >> 56)] ^ c1[int(k[1] >> 48) & 0xff] ^ c2[int(k[0] >> 40) & 0xff] ^ c3[int(k[7] >> 32) & 0xff] ^ c4[int(k[6] >> 24) & 0xff] ^ c5[int(k[5] >> 16) & 0xff] ^ c6[int(k[4] >> 8) & 0xff] ^ c7[int(k[3]) & 0xff]
		//
		l[3] = c0[int(k[3] >> 56)] ^ c1[int(k[2] >> 48) & 0xff] ^ c2[int(k[1] >> 40) & 0xff] ^ c3[int(k[0] >> 32) & 0xff] ^ c4[int(k[7] >> 24) & 0xff] ^ c5[int(k[6] >> 16) & 0xff] ^ c6[int(k[5] >> 8) & 0xff] ^ c7[int(k[4]) & 0xff]
		//
		l[4] = c0[int(k[4] >> 56)] ^ c1[int(k[3] >> 48) & 0xff] ^ c2[int(k[2] >> 40) & 0xff] ^ c3[int(k[1] >> 32) & 0xff] ^ c4[int(k[0] >> 24) & 0xff] ^ c5[int(k[7] >> 16) & 0xff] ^ c6[int(k[6] >> 8) & 0xff] ^ c7[int(k[5]) & 0xff]
		//
		l[5] = c0[int(k[5] >> 56)] ^ c1[int(k[4] >> 48) & 0xff] ^ c2[int(k[3] >> 40) & 0xff] ^ c3[int(k[2] >> 32) & 0xff] ^ c4[int(k[1] >> 24) & 0xff] ^ c5[int(k[0] >> 16) & 0xff] ^ c6[int(k[7] >> 8) & 0xff] ^ c7[int(k[6]) & 0xff]
		//
		l[6] = c0[int(k[6] >> 56)] ^ c1[int(k[5] >> 48) & 0xff] ^ c2[int(k[4] >> 40) & 0xff] ^ c3[int(k[3] >> 32) & 0xff] ^ c4[int(k[2] >> 24) & 0xff] ^ c5[int(k[1] >> 16) & 0xff] ^ c6[int(k[0] >> 8) & 0xff] ^ c7[int(k[7]) & 0xff]
		//
		l[7] = c0[int(k[7] >> 56)] ^ c1[int(k[6] >> 48) & 0xff] ^ c2[int(k[5] >> 40) & 0xff] ^ c3[int(k[4] >> 32) & 0xff] ^ c4[int(k[3] >> 24) & 0xff] ^ c5[int(k[2] >> 16) & 0xff] ^ c6[int(k[1] >> 8) & 0xff] ^ c7[int(k[0]) & 0xff]
		//
		for i := 0; i < 8; i++ {
			k[i] = l[i]
		}
		//
		l[0] = c0[int(state[0] >> 56)] ^ c1[int(state[7] >> 48) & 0xff] ^ c2[int(state[6] >> 40) & 0xff] ^ c3[int(state[5] >> 32) & 0xff] ^ c4[int(state[4] >> 24) & 0xff] ^ c5[int(state[3] >> 16) & 0xff] ^ c6[int(state[2] >> 8) & 0xff] ^ c7[int(state[1]) & 0xff] ^ k[0]
		//
		l[1] = c0[int(state[1] >> 56)] ^ c1[int(state[0] >> 48) & 0xff] ^ c2[int(state[7] >> 40) & 0xff] ^ c3[int(state[6] >> 32) & 0xff] ^ c4[int(state[5] >> 24) & 0xff] ^ c5[int(state[4] >> 16) & 0xff] ^ c6[int(state[3] >> 8) & 0xff] ^ c7[int(state[2]) & 0xff] ^ k[1]
		//
		l[2] = c0[int(state[2] >> 56)] ^ c1[int(state[1] >> 48) & 0xff] ^ c2[int(state[0] >> 40) & 0xff] ^ c3[int(state[7] >> 32) & 0xff] ^ c4[int(state[6] >> 24) & 0xff] ^ c5[int(state[5] >> 16) & 0xff] ^ c6[int(state[4] >> 8) & 0xff] ^ c7[int(state[3]) & 0xff] ^ k[2]
		//
		l[3] = c0[int(state[3] >> 56)] ^ c1[int(state[2] >> 48) & 0xff] ^ c2[int(state[1] >> 40) & 0xff] ^ c3[int(state[0] >> 32) & 0xff] ^ c4[int(state[7] >> 24) & 0xff] ^ c5[int(state[6] >> 16) & 0xff] ^ c6[int(state[5] >> 8) & 0xff] ^ c7[int(state[4]) & 0xff] ^ k[3]
		//
		l[4] = c0[int(state[4] >> 56)] ^ c1[int(state[3] >> 48) & 0xff] ^ c2[int(state[2] >> 40) & 0xff] ^ c3[int(state[1] >> 32) & 0xff] ^ c4[int(state[0] >> 24) & 0xff] ^ c5[int(state[7] >> 16) & 0xff] ^ c6[int(state[6] >> 8) & 0xff] ^ c7[int(state[5]) & 0xff] ^ k[4]
		//
		l[5] = c0[int(state[5] >> 56)] ^ c1[int(state[4] >> 48) & 0xff] ^ c2[int(state[3] >> 40) & 0xff] ^ c3[int(state[2] >> 32) & 0xff] ^ c4[int(state[1] >> 24) & 0xff] ^ c5[int(state[0] >> 16) & 0xff] ^ c6[int(state[7] >> 8) & 0xff] ^ c7[int(state[6]) & 0xff] ^ k[5]
		//
		l[6] = c0[int(state[6] >> 56)] ^ c1[int(state[5] >> 48) & 0xff] ^ c2[int(state[4] >> 40) & 0xff] ^ c3[int(state[3] >> 32) & 0xff] ^ c4[int(state[2] >> 24) & 0xff] ^ c5[int(state[1] >> 16) & 0xff] ^ c6[int(state[0] >> 8) & 0xff] ^ c7[int(state[7]) & 0xff] ^ k[6]
		//
		l[7] = c0[int(state[7] >> 56)] ^ c1[int(state[6] >> 48) & 0xff] ^ c2[int(state[5] >> 40) & 0xff] ^ c3[int(state[4] >> 32) & 0xff] ^ c4[int(state[3] >> 24) & 0xff] ^ c5[int(state[2] >> 16) & 0xff] ^ c6[int(state[1] >> 8) & 0xff] ^ c7[int(state[0]) & 0xff] ^ k[7]
		//
		for i := 0; i < 8; i++ {
			state[i] = l[i]
		}
		//
		n.intermediate_values(k, state)
	}
	//
	for i := 0; i < 8; i++ {
		n.hash[i] ^= (state[i] ^ block[i])
	}
}

//
fn (mut n Nessie) finalize() []byte {
	mut len := 0
	mut buffer_bits := n.buffer_bits
	mut buffer_pos := n.buffer_pos
	//
	n.buffer[buffer_pos] |= (byte(0x80) >> (buffer_bits & 7))
	buffer_pos++
	//
	if buffer_pos > vwhirlpool.wblock_bytes - vwhirlpool.length_bytes {
		if buffer_pos < vwhirlpool.wblock_bytes {
			// C.memset(n.buffer.data + buffer_pos, 0, wblock_bytes - buffer_pos)
			len = vwhirlpool.wblock_bytes - buffer_pos
			for i := 0; i < len; i++ {
				n.buffer[i + buffer_pos] = byte(0)
			}
		}
		//
		n.process()
		buffer_pos = 0
	}
	if buffer_pos < vwhirlpool.wblock_bytes - vwhirlpool.length_bytes {
		// C.memset(n.buffer.data + buffer_pos, 0, (wblock_bytes - length_bytes) - buffer_pos)
		len = ((vwhirlpool.wblock_bytes - vwhirlpool.length_bytes) - buffer_pos)
		for i := 0; i < len; i++ {
			n.buffer[i + buffer_pos] = byte(0)
		}
	}
	buffer_pos = vwhirlpool.wblock_bytes - vwhirlpool.length_bytes
	// C.memcpy(n.buffer.data + pos, n.bit_length.data, length_bytes)
	for i := 0; i < vwhirlpool.length_bytes; i++ {
		n.buffer[i + buffer_pos] = n.bit_length[i]
	}
	n.process()
	//
	mut digest := []byte{len: vwhirlpool.digest_bytes, init: 0}
	mut offset := 0
	for i := 0; i < vwhirlpool.digest_bytes / 8; i++ {
		digest[offset + 0] = byte(n.hash[i] >> 56)
		digest[offset + 1] = byte(n.hash[i] >> 48)
		digest[offset + 2] = byte(n.hash[i] >> 40)
		digest[offset + 3] = byte(n.hash[i] >> 32)
		digest[offset + 4] = byte(n.hash[i] >> 24)
		digest[offset + 5] = byte(n.hash[i] >> 16)
		digest[offset + 6] = byte(n.hash[i] >> 8)
		digest[offset + 7] = byte(n.hash[i])
		//
		offset += 8
	}
	//
	n.buffer_bits = buffer_bits
	n.buffer_pos = buffer_pos
	return digest
}

//
[if trace_intermediate_values]
fn (n &Nessie) print_derived() {
	mut offset := 0
	println('The 8x8 matrix z dereived from the data-string is as follows')
	for i := 0; i < vwhirlpool.wblock_bytes / 8; i++ {
		print('\t')
		print('${n.buffer[0 + offset]:02x}' + ' ')
		print('${n.buffer[1 + offset]:02x}' + ' ')
		print('${n.buffer[2 + offset]:02x}' + ' ')
		print('${n.buffer[3 + offset]:02x}' + ' ')
		print('${n.buffer[4 + offset]:02x}' + ' ')
		print('${n.buffer[5 + offset]:02x}' + ' ')
		print('${n.buffer[6 + offset]:02x}' + ' ')
		print('${n.buffer[7 + offset]:02x}' + ' ')
		println('')
		offset += 8
	}
	println('')
}

//
[if trace_intermediate_values]
fn (n &Nessie) intermediate_values(k []u64, state []u64) {
	for i := 0; i < vwhirlpool.digest_bytes / 8; i++ {
		print('${(k[i] >> 56):02x}' + ' ')
		print('${(k[i] >> 48):02x}' + ' ')
		print('${(k[i] >> 40):02x}' + ' ')
		print('${(k[i] >> 32):02x}' + ' ')
		print('${(k[i] >> 24):02x}' + ' ')
		print('${(k[i] >> 16):02x}' + ' ')
		print('${(k[i] >> 8):02x}' + ' ')
		print('${(k[i]):02x}' + ' ')
		print('\t\t')
		print('${(state[i] >> 56):02x}' + ' ')
		print('${(state[i] >> 48):02x}' + ' ')
		print('${(state[i] >> 40):02x}' + ' ')
		print('${(state[i] >> 32):02x}' + ' ')
		print('${(state[i] >> 24):02x}' + ' ')
		print('${(state[i] >> 16):02x}' + ' ')
		print('${(state[i] >> 8):02x}' + ' ')
		print('${(state[i]):02x}' + ' ')
		println('')
	}
	println('')
	println("The following are (hexadecimal representations of) the successive values of the variables K_i for i = 1 to 10 and W'")
	println('')
}
