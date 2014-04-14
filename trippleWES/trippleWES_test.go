package trippleWES

import "testing"

var key [10]uint8 = [10]uint8{1,2,3,4,5,6,7,8,9,1}

func TestPartialEncryptDecrypt(t *testing.T) {
    for i := uint8(0); i < uint8(255); i++ {
        ciphertext := EncryptFromArray(i, key)
        partialEncrypt := QuadruppleEncrypt(i, key[0], key[1], key[2], key[3])
        partialDecrypt := HextupleDecrypt(ciphertext, key[4], key[5], key[6], key[7], key[8], key[9])

        if partialDecrypt != partialEncrypt {
            t.Errorf("partialDecrypt = %v, want %v (1)", partialDecrypt, partialEncrypt)
        }
    }
}

func TestEncrypt(t *testing.T) {
    k := [10]uint8{0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xfe, 0xfc, 0xf8}
    if x := EncryptFromArray(uint8(0x41), k); x != uint8(0xa0) {
        t.Errorf("EncryptFromArray(uint8(0x41), k) = %v != uint8(0xa0)", x)
    }
}

func TestSbox(t *testing.T) {
    var in, out uint8 = uint8(190), uint8(134)

    x := sbox[in]
    x = (x >> 1) | (x << 7) // Invert shift

    if x != out {
        t.Errorf("sbox[%v] = %v, want %v (1)", in, x, out)
    }
}

func TestUnSbox(t *testing.T){
    for i := 0; i < len(sbox); i++ {
        if x := sboxInv[sbox[i]]; x != byte(i) {
            t.Errorf("sboxInv[sbox[%v]] = %v, want %v (1)", i, x, i)
        }
    }
}
