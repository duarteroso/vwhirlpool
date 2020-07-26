module vwhirlpool

fn test_empty() {
	input := hash("")
	output := "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3"
	assert input == output
}

fn test_string_a() {
	input := hash("a")
	output := "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A"
	assert input == output
}

fn test_string_abc() {
	input := hash("abc")
	output := "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5"
	assert input == output
}

fn test_string() {
	input := hash("The quick brown fox jumps over the lazy dog")
	output := "B97DE512E91E3828B40D2B0FDCE9CEB3C4A71F9BEA8D88E75C4FA854DF36725FD2B52EB6544EDCACD6F8BEDDFEA403CB55AE31F03AD62A5EF54E42EE82C3FB35"
	assert input == output
}

fn test_big_string() {
	input := hash("In computer science and cryptography, Whirlpool (sometimes styled WHIRLPOOL) is a cryptographic hash function. It was designed by Vincent Rijmen (co-creator of the Advanced Encryption Standard) and Paulo S. L. M. Barreto, who first described it in 2000. The hash has been recommended by the NESSIE project. It has also been adopted by the International Organization for Standardization (ISO) and the International Electrotechnical Commission (IEC) as part of the joint ISO/IEC 10118-3 international standard.")
	output := "78CB9C44A462ECA5E604C47071105713154C59629528D28999D7AB78ECA1591B7F95B2F5D6D3AD72ECE838DF06E37669362D7406438ACA9797AFF267FE6AC9ED"
	assert input == output
}
