package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
)

type keyEntry struct {
    Key [4]uint8
    DecryptedValues [8]uint8
}

func Crack(plaintext [12]uint8, ciphertext [12]uint8, start, end, numcpu int) {
    // CrackSerial(plaintext, ciphertext, start, end, 0, 110, numcpu)
    CrackSerial(plaintext, ciphertext, start, end, 110, 200, numcpu)
    CrackSerial(plaintext, ciphertext, start, end, 200, 256, numcpu)
}

func CrackSerial(plaintext [12]uint8, ciphertext [12]uint8, start, end, starti, endi, numcpu int) {
    var i,j,k,l uint8
    var ii, jj, kk, ll int

    i,j,k,l = uint8(starti), uint8(0), uint8(0), uint8(0)
    var keys [256][256][256][256][]keyEntry
    var decrypted [12]uint8

    for ii = starti; ii < endi; ii++ {
        for jj = 0; jj < 256; jj++ {
            for kk = 0; kk < 256; kk++ {
                for ll = 0; ll < 256; ll++ {
                    for x := 0; x < 12; x++ {
                        decrypted[x] = trippleWES.SeptupleDecrypt(ciphertext[x], i,j,k,l,l)
                    }

                    keys[decrypted[0]][decrypted[1]][decrypted[2]][decrypted[3]] = append(keys[decrypted[0]][decrypted[1]][decrypted[2]][decrypted[3]], keyEntry{ [4]uint8{i,j,k,l}, [8]uint8{decrypted[4], decrypted[5], decrypted[6], decrypted[7], decrypted[8], decrypted[9], decrypted[10], decrypted[11] } })

                    l++
                }
                l = uint8(0)
                k++
            }
            k = uint8(0)
            j++
        }
        j = uint8(0)
        fmt.Println("Finished key building round ", i)
        i++
    }

    fmt.Println("Finished building key dictionary")

    ch := make(chan int)
    stepSize := 256/numcpu
    for x := 0; x < numcpu; x++ {
        go parallelCrack(plaintext, ciphertext, (x*stepSize), (x*stepSize + stepSize), x, ch, &keys)
    }
    for x := 0; x < numcpu; x++ {
        id := <-ch
        fmt.Printf("\nThread %v finished.\n", id)
    }
}

func parallelCrack(plaintext, ciphertext [12]uint8, start, end, id int, ch chan int, keys *[256][256][256][256][]keyEntry) {
    // Let them know we're in action!
    fmt.Printf("Starting thread from i=%v to i=%v.\n", start, end)

    var i,j,k,l,m uint8
    var ii, jj, kk, ll, mm int
    var enc [5][12]uint8

    i,j,k,l,m = uint8(start), uint8(0), uint8(0), uint8(0), uint8(0)

    for ii = start; ii < end; ii++ { // (end-start) times
        for x := 0; x < 12; x++ {
            enc[0][x] = plaintext[x] ^ i
        }

        for jj = 0; jj < 256; jj++ { // 256*(end-start) times
            for x := 0; x < 12; x++ {
                enc[1][x] = trippleWES.Sbox[enc[0][x]] ^ j
            }

            for kk = 0; kk < 256; kk++ { // 65536*(end-start) times
                for x := 0; x < 12; x++ {
                    enc[2][x] = trippleWES.Sbox[enc[1][x]] ^ k
                }

                for ll = 0; ll < 256; ll++ { // 16777216*(end-start) times -- sixteen million
                    for x := 0; x < 12; x++ {
                        enc[3][x] = trippleWES.Sbox[enc[2][x]] ^ l
                    }

                    for mm = 0; mm < 256; mm++ { // 4294967296*(end-start) times -- four billion
                        for x := 0; x < 12; x++ {
                            enc[4][x] = trippleWES.Sbox[enc[3][x]] ^ m
                        }

                        for _, key := range keys[enc[4][0]][enc[4][1]][enc[4][2]][enc[4][3]] {
                            if testGoodKey(enc[4], key) {
                                fmt.Println("\n\n\n FOUNDKEY \n\n\n")
                                fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b %8b %8b \n", i,j,k,l,m,key.Key[0],key.Key[1],key.Key[2],key.Key[3],key.Key[3])
                                fmt.Printf("         = %v  %v  %v  %v  %v  %v  %v  %v  %v  %v \n",  i,j,k,l,m,key.Key[0],key.Key[1],key.Key[2],key.Key[3],key.Key[3])
                                return
                            }
                        }
                        m++
                    }
                    m = uint8(0)
                    l++
                }
                l = uint8(0)
                k++
            }
            k = uint8(0)

            if j%16 == 0 {
                fmt.Printf(" (#%v.%v) ",i,j)                
            }
            j++
        }
        j = uint8(0)
        fmt.Printf("\nFinished level 1 (#%v)round breaking keys\n",i)
        i++
    }

    // Finished!
    ch <- id
}

func testGoodKey(encrypted [12]uint8, keyEntry keyEntry) (bool) {
    // 0, 1 and 2 already match; skip checking those!
    for x := 0; x < 8; x++ {
        if keyEntry.DecryptedValues[x] != encrypted[x + 4] {
            return false
        }
    }

    return true
}
