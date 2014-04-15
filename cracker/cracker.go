package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
)

// First sorted by output, then no sort
var keys [256][256][256][][3]uint8 // store [output][position][key]


func Crack(plaintext [12]uint8, ciphertext [12]uint8, start, end int) {
    var i,j,k,l,m,n uint8
    var ii, jj, kk, ll, mm, nn int
    var dec0, dec1, dec2 uint8

    for ii = 0; ii < 256; ii++ {
        i = uint8(ii)
        for jj = 0; jj < 256; jj++ {
            j = uint8(jj)
            for kk = 0; kk < 256; kk++ {
                k = uint8(kk)
                dec0 = trippleWES.QuadrupleDecrypt(ciphertext[0], i, j, k, k)
                dec1 = trippleWES.QuadrupleDecrypt(ciphertext[1], i, j, k, k)
                dec2 = trippleWES.QuadrupleDecrypt(ciphertext[2], i, j, k, k)

                keys[dec0][dec1][dec2] = append(keys[dec0][dec1][dec2], [3]uint8{i,j,k})
            }
        }
    }

    fmt.Println("Finished building key dictionary")
    
    var enc0, enc1, enc2 [6]uint8

    i,j,k,l,m,n = uint8(0), uint8(0), uint8(0), uint8(0), uint8(0), uint8(0)

    for ii = start; ii < end; ii++ {
        enc0[0] = plaintext[0] ^ i
        enc1[0] = plaintext[1] ^ i
        enc2[0] = plaintext[2] ^ i

        for jj = 0; jj < 256; jj++ {
            enc0[1] = trippleWES.Sbox[enc0[0]] ^ j
            enc1[1] = trippleWES.Sbox[enc1[0]] ^ j
            enc2[1] = trippleWES.Sbox[enc2[0]] ^ j

            for kk = 0; kk < 256; kk++ {
                enc0[2] = trippleWES.Sbox[enc0[1]] ^ k
                enc1[2] = trippleWES.Sbox[enc1[1]] ^ k
                enc2[2] = trippleWES.Sbox[enc2[1]] ^ k

                for ll = 0; ll < 256; ll++ {
                    enc0[3] = trippleWES.Sbox[enc0[2]] ^ l
                    enc1[3] = trippleWES.Sbox[enc1[2]] ^ l
                    enc2[3] = trippleWES.Sbox[enc2[2]] ^ l

                    for mm = 0; mm < 256; mm++ {
                        enc0[4] = trippleWES.Sbox[enc0[3]] ^ m
                        enc1[4] = trippleWES.Sbox[enc1[3]] ^ m
                        enc2[4] = trippleWES.Sbox[enc2[3]] ^ m

                        for nn = 0; nn < 256; nn++ {
                            enc0[5] = trippleWES.Sbox[enc0[4]] ^ n
                            enc1[5] = trippleWES.Sbox[enc1[4]] ^ n
                            enc2[5] = trippleWES.Sbox[enc2[4]] ^ n

                            if keys[enc0[5]][enc1[5]][enc2[5]] != nil {
                                for _, key := range keys[enc0[5]][enc1[5]][enc2[5]] {
                                    testGoodKey(i,j,k,l,m,n, &key, &plaintext, &ciphertext)
                                }
                            }
                            n++
                        }
                        m++
                    }
                    l++
                }
                k++
            }
            fmt.Printf(" (#%v.%v) ",i,j)
            j++
        }
        fmt.Printf("\nFinished level 1 (#%v)round breaking keys\n",i)
        i++
    }
}

func testGoodKey(i,j,k,l,m,n uint8, key *[3]uint8, plaintext, ciphertext *[12]uint8) {
    // 0, 1 and 2 already match; skip checking those!
    for x := 3; x < 12; x++ {
        cip := trippleWES.Encrypt(plaintext[x], i,j,k,l,m,n,key[0],key[1],key[2],key[2])
        if cip != ciphertext[x] {
            return
        }
    }
    fmt.Println("\n\n\n FOUNDKEY \n\n\n")
    fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b %8b %8b \n", i,j,k,l,m,key[0],key[1],key[2],key[2],key[2])
    fmt.Printf("         = %v  %v  %v  %v  %v  %v  %v  %v  %v  %v \n",  i,j,k,l,m,key[0],key[1],key[2],key[2],key[2])
}
