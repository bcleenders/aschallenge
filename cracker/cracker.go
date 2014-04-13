package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
    "time"
)

const ZERO = uint8(0)
const MAX = uint8(255)
const ARRSIZE = 256*256

// First sorted by output, then no sort
var keys [256][256][256][3]uint8 // store [output][position][key]


func Crack(plaintext [12]uint8, ciphertext [12]uint8) {
    var i,j,k,l uint8

    var dec0, dec1, dec2 uint8

    for i = ZERO; i < MAX; i++ {
        for j = ZERO; j < MAX; j++ {
            for k = ZERO; k < MAX; k++ {
                dec0 = trippleWES.HextupleDecrypt(ciphertext[0], i, j, k, k, k, k)
                dec1 = trippleWES.HextupleDecrypt(ciphertext[1], i, j, k, k, k, k)
                dec2 = trippleWES.HextupleDecrypt(ciphertext[2], i, j, k, k, k, k)

                if keys[dec0][dec1][dec2] != [3]uint8{0,0,0} {
                    fmt.Println("Collision!")
                }
                keys[dec0][dec1][dec2] = [3]uint8{i,j,k}
            }
        }


        if i == 128 {
            fmt.Println("Halfway building keyStores")
        }
    }

    fmt.Println("Finished building keyStores")
    fmt.Println(keys)
    
    started := time.Now()

    var enc0, enc1, enc2 uint8

    for i = ZERO; i < MAX; i++ {
        for j = ZERO; j < MAX; j++ {
            for k = ZERO; k < MAX; k++ {
                for l = ZERO; l < MAX; l++ {
                    enc0 = trippleWES.QuadruppleEncrypt(plaintext[0], i, j, k, l)
                    enc1 = trippleWES.QuadruppleEncrypt(plaintext[1], i, j, k, l)
                    enc2 = trippleWES.QuadruppleEncrypt(plaintext[2], i, j, k, l)

                    testGoodKey(i,j,k,l, &keys[enc0][enc1][enc2], &plaintext, &ciphertext)
                }
                // fmt.Println("Finished level 3 round breaking keys")
            }
            // Occurs 256*256 = 65336 times
            // fmt.Printf("Finished level 2 round breaking keys (%v)\n", time.Since(started))
        }
        fmt.Printf("Finished level 1 (#%v)round breaking keys (%v)\n",i, time.Since(started))
    }
}

func testGoodKey(i,j,k,l uint8, key *[3]uint8, plaintext, ciphertext *[12]uint8) {
    for n := 0; n < 12; n++ {
        cip := trippleWES.Encrypt(plaintext[n], i,j,k,l,key[0],key[1],key[2],key[2],key[2],key[2])
        if cip != ciphertext[n] {
            return
        }
        if n == 2 { // remember: we started at zero!
            fmt.Println("Found one that matches five pairs!")
        }
    }
    fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b ", i,j,k,l,key[0],key[1],key[2],key[2],key[2],key[2])
}
