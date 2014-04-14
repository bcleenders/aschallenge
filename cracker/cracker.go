package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
    "time"
)

const ZERO = uint8(0)
const MAX = uint8(255)

// First sorted by output, then no sort
var keys [256][256][256][][3]uint8 // store [output][position][key]


func Crack(plaintext [12]uint8, ciphertext [12]uint8) {
    var i,j,k,l uint8

    // collisions := 0

    var dec0, dec1, dec2 uint8
    var ii, jj, kk int
    // Store first three key bytes
    fmt.Println("Starting building the dictionary")
    for ii = 0; ii < 256; ii++ {
        i = int(ii)
        for jj = 0; jj < 256; jj++ {
            j = int(jj)
            for kk = 0; kk < 256; kk++ {
                k = int(kk)

                dec0 = trippleWES.TrippleEncrypt(plaintext[0], i, j, k)
                dec1 = trippleWES.TrippleEncrypt(plaintext[1], i, j, k)
                dec2 = trippleWES.TrippleEncrypt(plaintext[2], i, j, k)

                // if keys[dec0][dec1][dec2] != nil {
                //     fmt.Println("Collision!", keys[dec0][dec1][dec2], [3]uint8{i,j,k}, dec0, dec1, dec2)
                //     collisions++
                // }
                keys[dec0][dec1][dec2] = append(keys[dec0][dec1][dec2], [3]uint8{i,j,k})
            }
        }


        if i == 128 {
            fmt.Println("Halfway building dictionary")
        }
    }

    // fmt.Printf("Collisions: %v     -   %.2f%%", collisions, 100*(float64(collisions)/float64(256*256*256)))

    fmt.Println("Finished building dictionary")
    // fmt.Println(keys)
    
    started := time.Now()

    var enc0, enc1, enc2 uint8

    for i = ZERO; i < MAX; i++ {
        for j = ZERO; j < MAX; j++ {
            for k = ZERO; k < MAX; k++ {
                for l = ZERO; l < MAX; l++ {
                    enc0 = trippleWES.SeptupleDecrypt(ciphertext[0], i, j, k, l, l, l, l)
                    enc1 = trippleWES.SeptupleDecrypt(ciphertext[1], i, j, k, l, l, l, l)
                    enc2 = trippleWES.SeptupleDecrypt(ciphertext[2], i, j, k, l, l, l, l)

                    for _, key := range keys[enc0][enc1][enc2] {
                        if key != [3]uint8{0,0,0} {
                            testGoodKey(i,j,k,l, &key, &plaintext, &ciphertext)
                        } else {
                            fmt.Println("bla")
                        }
                    }
                }
            }
        }
        fmt.Printf("Finished level 1 (#%v)round breaking keys (%v)\n",i, time.Since(started))
    }
}

func testGoodKey(i,j,k,l uint8, key *[3]uint8, plaintext, ciphertext *[12]uint8) {
    // if trippleWES.Encrypt(plaintext[0], key[0],key[1],key[2],i,j,k,l,l,l,l) != ciphertext[0] {
    //     fmt.Println(plaintext[0], trippleWES.Encrypt(plaintext[0], key[0],key[1],key[2],i,j,k,l,l,l,l), ciphertext[0])
    //     fmt.Println(key[0],key[1],key[2],i,j,k,l,l,l,l)
    //     fmt.Println("SeptupleDecrypt: ", trippleWES.SeptupleDecrypt(plaintext[0], i, j, k, l, l, l, l))
    //     fmt.Println("TrippleEncrypt:  ", trippleWES.TrippleEncrypt(ciphertext[0], key[0],key[1],key[2]))
    //     fmt.Println("method fails; encrypted text does not match ciphertext.")
    // }

    for n := 0; n < 12; n++ {
        cip := trippleWES.Encrypt(plaintext[n], key[0],key[1],key[2],i,j,k,l,l,l,l)
        if cip != ciphertext[n] {
            return
        }
        if n == 4 { // remember: we started at zero!
            fmt.Println("Found one that matches five pairs!")
        }
    }
    fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b ", i,j,k,l,key[0],key[1],key[2],key[2],key[2],key[2])
}
