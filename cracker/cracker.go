package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
)

const ZERO = uint8(0)
const MAX = uint8(255)
const ARRSIZE = 256*256

var keyStores [3][256][256*256]int // store [output][position][key]
var positions [3][256]int // Keeps track of the positions in hasDouble

func Crack(plaintext [12]uint8, ciphertext [12]uint8) {
    var i,j,k,l uint8
    var dec0, dec1, dec2 uint8
    var keyAsInt int

    for i = ZERO; i < MAX; i++ {
        for j = ZERO; j < MAX; j++ {
            for k = ZERO; k < MAX; k++ {

                keyAsInt = 256*256*int(i) + 256*int(j) + 256*int(k)

                dec0 = trippleWES.HextupleDecrypt(ciphertext[0], i, j, k, k, k, k)
                dec1 = trippleWES.HextupleDecrypt(ciphertext[1], i, j, k, k, k, k)
                dec2 = trippleWES.HextupleDecrypt(ciphertext[2], i, j, k, k, k, k)

                keyStores[0][dec0][positions[0][dec0]] = keyAsInt
                positions[0][dec0]++

                keyStores[1][dec1][positions[1][dec1]] = keyAsInt
                positions[1][dec1]++

                keyStores[2][dec2][positions[2][dec2]] = keyAsInt
                positions[2][dec2]++
            }
        }


        if i == 128 {
            fmt.Println("Halfway building keyStores")
        }
    }

    fmt.Println("Finished building keyStores")

    for i = ZERO; i < MAX; i++ {
        for j = ZERO; j < MAX; j++ {
            for k = ZERO; k < MAX; k++ {
                for l = ZERO; l < MAX; l++ {
                    enc0 := trippleWES.QuadruppleEncrypt(plaintext[0], i, j, k, l)
                    enc1 := trippleWES.QuadruppleEncrypt(plaintext[1], i, j, k, l)
                    enc2 := trippleWES.QuadruppleEncrypt(plaintext[2], i, j, k, l)

                    // Now find the keys that match
                    findMatching(i, j, k, l, &plaintext, &ciphertext, enc0, enc1, enc2)
                    // keycount, keys := findSorted(&keyStores[0][enc0], &keyStores[1][enc1], i, j, k, l, plaintext, ciphertext))
                }
                fmt.Println("Finished level 3 round breaking keys")
            }
            fmt.Println("Finished level 2 round breaking keys")
        }
        fmt.Println("Finished level 1 round breaking keys")
    }
}

func testKey(key0, key1, key2, key3 uint8, trailingKey int, plaintext, ciphertext *[12]uint8) (bool) {
    trailingkey0 := uint8((trailingKey >> 16) % 255)
    trailingkey1 := uint8((trailingKey >> 8) % 255)
    trailingkey2 := uint8(trailingKey % 255)

    for j := 2; j < 12; j++ {
        if trippleWES.Encrypt(plaintext[j], key0, key1, key2, key3, trailingkey0, trailingkey1, trailingkey2, trailingkey2, trailingkey2, trailingkey2) != ciphertext[j] {
            return false
        }
    }

    return true
}

func findMatching(key0, key1, key2, key3 uint8, plaintext, ciphertext *[12]uint8, cip0, cip1, cip2 uint8) () {
    var pos0, pos1, pos2 int
    //var count0, count1, count2 int

    for (pos0 < positions[0][cip0] && pos1 < positions[1][cip1] && pos2 < positions[2][cip2]) {

        if keyStores[0][cip0][pos0] > keyStores[1][cip1][pos1] {
            pos1++
        } 

        if keyStores[1][cip1][pos1] > keyStores[2][cip2][pos2] {
            pos2++
        } 

        if keyStores[2][cip2][pos2] > keyStores[0][cip0][pos0] {
            pos0++
        }

        if keyStores[0][cip0][pos0] == keyStores[1][cip1][pos1] && keyStores[1][cip1][pos1] == keyStores[2][cip2][pos2] {
            // count1++
            if testKey(key0, key1, key2, key3, keyStores[0][cip0][pos0], plaintext, ciphertext) {
                trailingkey0 := uint8((keyStores[0][cip0][pos0] >> 16) % 255)
                trailingkey1 := uint8((keyStores[0][cip0][pos0] >> 8)  % 255)
                trailingkey2 := uint8( keyStores[0][cip0][pos0]        % 255)
                fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b %8b %8b \n", key0, key1, key2, key3, trailingkey0, trailingkey1, trailingkey2, trailingkey2, trailingkey2, trailingkey2)
            }
            pos0++
            pos1++
            pos2++
        }

        // if (pos0 + pos1) % 20000 == 0 {
        //     fmt.Printf("a>b = %v, a==b= %v, a<b=%v\n", count0, count1, count2)
        // }
    }
}
