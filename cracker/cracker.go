package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
)

// First sorted by output, then no sort
var keys [256][256][256][][3]uint8 // store [output][position][key]


func Crack(plaintext [12]uint8, ciphertext [12]uint8) {
    var i,j,k,l uint8
    var ii, jj, kk, ll int
    var dec0, dec1, dec2 uint8

    for ii = 0; ii < 256; ii++ {
        i = uint8(ii)
        for jj = 0; jj < 256; jj++ {
            j = uint8(jj)
            for kk = 0; kk < 256; kk++ {
                k = uint8(kk)
                dec0 = trippleWES.HextupleDecrypt(ciphertext[0], i, j, k, k, k, k)
                dec1 = trippleWES.HextupleDecrypt(ciphertext[1], i, j, k, k, k, k)
                dec2 = trippleWES.HextupleDecrypt(ciphertext[2], i, j, k, k, k, k)

                keys[dec0][dec1][dec2] = append(keys[dec0][dec1][dec2], [3]uint8{i,j,k})
            }
        }
    }
    
    var enc0, enc1, enc2 uint8

    for ii = 0; ii < 256; ii++ {
        i = uint8(ii)
        for jj = 0; jj < 256; jj++ {
            j = uint8(jj)
            for kk = 0; kk < 256; kk++ {
                k = uint8(kk)
                for ll = 0; ll < 256; ll++ {
                    l = uint8(ll)

                    enc0 = trippleWES.QuadruppleEncrypt(plaintext[0], i, j, k, l)
                    enc1 = trippleWES.QuadruppleEncrypt(plaintext[1], i, j, k, l)
                    enc2 = trippleWES.QuadruppleEncrypt(plaintext[2], i, j, k, l)

                    for _, key := range keys[enc0][enc1][enc2] {
                        // if ciphertext[0] != trippleWES.Encrypt(plaintext[0], i,j,k,l,keys[enc0][enc1][enc2][0][0],keys[enc0][enc1][enc2][0][1],keys[enc0][enc1][enc2][0][2],keys[enc0][enc1][enc2][0][2],keys[enc0][enc1][enc2][0][2],keys[enc0][enc1][enc2][0][2]) {
                        //     fmt.Println("Ciphertext did not match")
                        // } else {
                        //     fmt.Println("Ciphertext did match")
                        // }
                        testGoodKey(i,j,k,l, &key, &plaintext, &ciphertext)
                    }
                }
                // fmt.Println("Finished level 3 round breaking keys")
            }
            // Occurs 256*256 = 65336 times
            // fmt.Printf("Finished level 2 round breaking keys (%v)\n", time.Since(started))
        }

        fmt.Printf("Finished level 1 (#%v)round breaking keys\n",i)
    }
}

func testGoodKey(i,j,k,l uint8, key *[3]uint8, plaintext, ciphertext *[12]uint8) {
    for n := 0; n < 12; n++ {
        cip := trippleWES.Encrypt(plaintext[n], i,j,k,l,key[0],key[1],key[2],key[2],key[2],key[2])
        if cip != ciphertext[n] {
            return
        }
        // if n == 2 { // remember: we started at zero!
        //     fmt.Println("Found one that matches five pairs!")
        // }
    }
    fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b %8b %8b \n", i,j,k,l,key[0],key[1],key[2],key[2],key[2],key[2])
    fmt.Printf("         = %v  %v  %v  %v  %v  %v  %v  %v  %v  %v \n", i,j,k,l,key[0],key[1],key[2],key[2],key[2],key[2])
}
