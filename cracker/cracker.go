package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
)

const ZERO = uint8(0)
const MAX = uint8(255)
const ARRSIZE = 256*256

func Crack(plaintext [12]uint8, ciphertext [12]uint8) {
    var i,j,k,l uint8

    // First sorted by output, then no sort
    var keyStore0, keyStore1 [256][256*256]int // store [output][position][key]
    var position0, position1 [256]int // Keeps track of the positions in hasDouble
    var dec0, dec1 uint8

    for i = ZERO; i < MAX; i++ {
        for j = ZERO; j < MAX; j++ {
            for k = ZERO; k < MAX; k++ {
                dec0 = trippleWES.HextupleDecrypt(ciphertext[0], i, j, k, k, k, k)
                dec1 = trippleWES.HextupleDecrypt(ciphertext[1], i, j, k, k, k, k)

                keyStore0[dec0][position0[dec0]] = 256*256*int(i) + 256*int(j) + 256*int(k)
                position0[dec0]++

                keyStore1[dec1][position1[dec1]] = 256*256*int(i) + 256*int(j) + 256*int(k)
                position1[dec1]++
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

                    // Now find the keys that match
                    findMatching(&keyStore0[enc0], &keyStore1[enc1], i, j, k, l, &plaintext, &ciphertext)
                    // keycount, keys := findSorted(&keyStore0[enc0], &keyStore1[enc1], i, j, k, l, plaintext, ciphertext))
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

func findMatching(keys0, keys1 *[256*256]int, key0, key1, key2, key3 uint8, plaintext, ciphertext *[12]uint8) () {
    var pos0, pos1 int
    //var count0, count1, count2 int

    for (pos0 < ARRSIZE && pos1 < ARRSIZE) {
        if keys0[pos0] > keys1[pos1] { //islarger(keys0[pos0], keys1[pos1]) {
            // count0++
            pos0++
        } else if keys0[pos0] == keys1[pos1] {
            // count1++
            if testKey(key0, key1, key2, key3, keys0[pos0], plaintext, ciphertext) {
                trailingkey0 := uint8((keys0[pos0] >> 16) % 255)
                trailingkey1 := uint8((keys0[pos0] >> 8)  % 255)
                trailingkey2 := uint8( keys0[pos0]        % 255)
                fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b %8b %8b \n", key0, key1, key2, key3, trailingkey0, trailingkey1, trailingkey2, trailingkey2, trailingkey2, trailingkey2)
            }
            pos0++
            pos1++
        } else {
            // count2++
            pos1++
        }

        // if (pos0 + pos1) % 20000 == 0 {
        //     fmt.Printf("a>b = %v, a==b= %v, a<b=%v\n", count0, count1, count2)
        // }
    }
}
