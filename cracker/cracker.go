package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
)

// First sorted by output, then no sort
var keys [256][256][256][][3]uint8 // store [output][position][key]


func Crack(plaintext [12]uint8, ciphertext [12]uint8, start, end int) {
    var i,j,k,l,m uint8
    var ii, jj, kk, ll, mm int
    var dec0, dec1, dec2 uint8

    for ii = 0; ii < 256; ii++ {
        i = uint8(ii)
        for jj = 0; jj < 256; jj++ {
            j = uint8(jj)
            for kk = 0; kk < 256; kk++ {
                k = uint8(kk)
                dec0 = trippleWES.SeptupleDecrypt(ciphertext[0], i, j, k, k, k)
                dec1 = trippleWES.SeptupleDecrypt(ciphertext[1], i, j, k, k, k)
                dec2 = trippleWES.SeptupleDecrypt(ciphertext[2], i, j, k, k, k)

                keys[dec0][dec1][dec2] = append(keys[dec0][dec1][dec2], [3]uint8{i,j,k})
            }
        }
    }

    fmt.Println("Finished building key dictionary")
    
    var enc0, enc1, enc2 uint8

    for ii = start; ii < end; ii++ {
        i = uint8(ii)
        for jj = 0; jj < 256; jj++ {
            j = uint8(jj)
            for kk = 0; kk < 256; kk++ {
                k = uint8(kk)
                for ll = 0; ll < 256; ll++ {
                    l = uint8(ll)
                    for mm = 0; mm < 256; mm++ {
                        m = uint8(mm)

                        enc0 = trippleWES.SeptupleEncrypt(plaintext[0], i, j, k, l,m)
                        enc1 = trippleWES.SeptupleEncrypt(plaintext[1], i, j, k, l,m)
                        enc2 = trippleWES.SeptupleEncrypt(plaintext[2], i, j, k, l,m)

                        for _, key := range keys[enc0][enc1][enc2] {
                            testGoodKey(i,j,k,l,m, &key, &plaintext, &ciphertext)
                        }
                    }
                }
                // if kk % 10 == 0 {
                //     fmt.Printf(".")
                // }
            }
            fmt.Printf("%v.%v\n",ii,jj)
        }
        fmt.Printf("\nFinished level 1 (#%v)round breaking keys\n",i)
    }
}

func testGoodKey(i,j,k,l,m uint8, key *[3]uint8, plaintext, ciphertext *[12]uint8) {
    // 0, 1 and 2 already match; skip checking those!
    for n := 3; n < 12; n++ {
        cip := trippleWES.Encrypt(plaintext[n], i,j,k,l,m,key[0],key[1],key[2],key[2],key[2])
        if cip != ciphertext[n] {
            return
        }
    }
    fmt.Println()
    fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b %8b %8b \n", i,j,k,l,m,key[0],key[1],key[2],key[2],key[2])
    fmt.Printf("         = %v  %v  %v  %v  %v  %v  %v  %v  %v  %v \n",  i,j,k,l,m,key[0],key[1],key[2],key[2],key[2])
}
