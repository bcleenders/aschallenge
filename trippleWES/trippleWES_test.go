package trippleWES

import "testing"

var key [10]uint8 = [10]uint8{1,2,3,4,5,6,7,8,9,1}

func testPartialEncryptDecrypt(t *testing.T) {
    for i := uint8(0); i <= uint8(255); i++ {
        ciphertext := EncryptFromArray(i, key)
        partialEncrypt := QuadruppleEncrypt(i, key[0], key[1], key[2], key[3])
        partialDecrypt := HextupleDecrypt(ciphertext, key[4], key[5], key[6], key[7], key[8], key[9])

        if partialDecrypt != partialEncrypt {
            t.Errorf("partialDecrypt == %v, want %v (1)", partialDecrypt, partialEncrypt)
        }
    }
}

func testSbox(t *testing.T) {
    var in, out byte = byte(190), byte(134)

    if x := sbox[in]; x != out {
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
