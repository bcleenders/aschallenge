package trippleWES

// Includes the shift!
var sbox [256]uint8 = [256]uint8{0, 2, 27, 237, 151, 164, 246, 163, 209, 158, 82, 129, 97, 195, 203, 143, 232, 105, 85, 150, 51, 86, 192, 190, 176, 126, 251, 153, 255, 128, 221, 101, 116, 220, 180, 227, 170, 154, 81, 147, 131, 20, 49, 42, 96, 136, 69, 133, 88, 138, 37, 216, 231, 114, 204, 132, 229, 106, 64, 222, 238, 119, 178, 50, 58, 253, 110, 206, 90, 98, 235, 210, 79, 200, 87, 38, 168, 74, 211, 18, 219, 184, 10, 149, 152, 72, 15, 127, 48, 124, 68, 225, 162, 217, 194, 46, 44, 188, 95, 167, 146, 77, 108, 134, 233, 142, 35, 191, 102, 39, 66, 118, 242, 111, 47, 11, 32, 107, 117, 120, 109, 224, 161, 12, 67, 245, 3, 5, 7, 252, 254, 1, 45, 230, 125, 172, 55, 61, 43, 179, 239, 4, 115, 73, 189, 212, 100, 218, 177, 21, 9, 228, 84, 40, 63, 17, 243, 185, 19, 53, 247, 248, 92, 135, 31, 113, 202, 144, 76, 145, 36, 148, 157, 207, 165, 196, 24, 193, 62, 223, 34, 234, 240, 226, 75, 29, 236, 122, 123, 121, 13, 174, 22, 80, 94, 71, 181, 169, 201, 30, 83, 78, 166, 8, 54, 249, 89, 205, 244, 14, 93, 198, 139, 183, 197, 213, 41, 23, 137, 171, 59, 241, 33, 214, 99, 26, 173, 215, 141, 28, 159, 91, 16, 156, 175, 199, 186, 160, 60, 103, 182, 70, 112, 104, 208, 140, 6, 25, 187, 57, 250, 65, 155, 52, 130, 56}
var sboxInv [256]uint8 = [256]uint8{0, 131, 1, 126, 141, 127, 246, 128, 203, 150, 82, 115, 123, 190, 209, 86, 232, 155, 79, 158, 41, 149, 192, 217, 176, 247, 225, 2, 229, 185, 199, 164, 116, 222, 180, 106, 170, 50, 75, 109, 153, 216, 43, 138, 96, 132, 95, 114, 88, 42, 63, 20, 253, 159, 204, 136, 255, 249, 64, 220, 238, 137, 178, 154, 58, 251, 110, 124, 90, 46, 241, 195, 85, 143, 77, 184, 168, 101, 201, 72, 193, 38, 10, 200, 152, 18, 21, 74, 48, 206, 68, 231, 162, 210, 194, 98, 44, 12, 69, 224, 146, 31, 108, 239, 243, 17, 57, 117, 102, 120, 66, 113, 242, 165, 53, 142, 32, 118, 111, 61, 119, 189, 187, 188, 89, 134, 25, 87, 29, 11, 254, 40, 55, 47, 103, 163, 45, 218, 49, 212, 245, 228, 105, 15, 167, 169, 100, 39, 171, 83, 19, 4, 84, 27, 37, 252, 233, 172, 9, 230, 237, 122, 92, 7, 5, 174, 202, 99, 76, 197, 36, 219, 135, 226, 191, 234, 24, 148, 62, 139, 34, 196, 240, 213, 81, 157, 236, 248, 97, 144, 23, 107, 22, 177, 94, 13, 175, 214, 211, 235, 73, 198, 166, 14, 54, 207, 67, 173, 244, 8, 71, 78, 145, 215, 223, 227, 51, 93, 147, 80, 33, 30, 59, 179, 121, 91, 183, 35, 151, 56, 133, 52, 16, 104, 181, 70, 186, 3, 60, 140, 182, 221, 112, 156, 208, 125, 6, 160, 161, 205, 250, 26, 129, 65, 130, 28}

func encrypt(plaintext uint8, key uint8) (uint8) {
    return sbox[plaintext] ^ key
}

func decrypt(ciphertext uint8, key uint8) (uint8) {
    return sboxInv[ciphertext ^ key]
}

func Encrypt(plaintext, key0, key1, key2, key3, key4, key5, key6, key7, key8, key9 uint8) (uint8) {
    plaintext ^= key0
    plaintext = sbox[plaintext] ^ key1
    plaintext = sbox[plaintext] ^ key2
    plaintext = sbox[plaintext] ^ key3
    plaintext = sbox[plaintext] ^ key4
    plaintext = sbox[plaintext] ^ key5
    plaintext = sbox[plaintext] ^ key6
    plaintext = sbox[plaintext] ^ key7
    plaintext = sbox[plaintext] ^ key8
    plaintext = sbox[plaintext] ^ key9

    return plaintext
}

func Decrypt(ciphertext, key0, key1, key2, key3, key4, key5, key6, key7, key8, key9 uint8) (uint8) {
    ciphertext ^= key9
    ciphertext = sboxInv[ciphertext] ^ key8
    ciphertext = sboxInv[ciphertext] ^ key7
    ciphertext = sboxInv[ciphertext] ^ key6
    ciphertext = sboxInv[ciphertext] ^ key5
    ciphertext = sboxInv[ciphertext] ^ key4
    ciphertext = sboxInv[ciphertext] ^ key3
    ciphertext = sboxInv[ciphertext] ^ key2
    ciphertext = sboxInv[ciphertext] ^ key1
    ciphertext = sboxInv[ciphertext] ^ key0

    return ciphertext
}

func HextupleDecrypt(ciphertext uint8, key4, key5, key6, key7, key8, key9 uint8) (uint8) {
    ciphertext ^= key9
    ciphertext = sboxInv[ciphertext] ^ key8
    ciphertext = sboxInv[ciphertext] ^ key7
    ciphertext = sboxInv[ciphertext] ^ key6
    ciphertext = sboxInv[ciphertext] ^ key5
    ciphertext = sboxInv[ciphertext] ^ key4
    ciphertext = sboxInv[ciphertext]

    return ciphertext
}

/*
    Do a partial encrypt; first four bytes only.
    Key1 is used for the key whitening, key 2,3&4 are used for regular encryption rounds.
*/
func QuadruppleEncrypt(plaintext uint8, key0, key1, key2, key3 uint8) (uint8) {
    plaintext ^= key0
    plaintext = sbox[plaintext] ^ key1
    plaintext = sbox[plaintext] ^ key2
    plaintext = sbox[plaintext] ^ key3

    return plaintext
}

func EncryptFromArray(plaintext uint8, key [10]uint8) (uint8) {
    return Encrypt(plaintext, key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9])
}
