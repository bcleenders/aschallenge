package cracker

import(
    "fmt"
    "github.com/bcleenders/security_challenge/trippleWES"
)

type keyEntry struct {
    Key [4]uint8
    DecryptedValues [8]uint8
}

func Crack(plaintext [12]uint8, ciphertext [12]uint8, start, end, memSteps, numcpu int) {
    for startKeys := 0; startKeys < 256; startKeys = startKeys + memSteps {
        endKeys := startKeys + memSteps
        if endKeys > 256 {
            endKeys = 256
        }
        
        crackSerial(plaintext, ciphertext, start, end, numcpu, startKeys, endKeys)
    }
}

func crackSerial(plaintext [12]uint8, ciphertext [12]uint8, start, end, numcpu, startKeys, endKeys int) {
    var i,j,k,l uint8
    var ii, jj, kk, ll int

    i,j,k,l = uint8(startKeys), uint8(0), uint8(0), uint8(0)
    var keys [256][256][256][256][]keyEntry
    var decrypted [5][12]uint8

    for ii = startKeys; ii < endKeys; ii++ {
        for x := 0; x < 12; x++ {
            decrypted[0][x] = ciphertext[x] ^ i
        }

        for jj = 0; jj < 256; jj++ {
            for x := 0; x < 12; x++ {
                decrypted[1][x] = trippleWES.SboxInv[decrypted[0][x]] ^ j
            }

            // TEST ME WITH 2
            for kk = 0; kk < 256; kk++ {
                for x := 0; x < 12; x++ {
                    decrypted[2][x] = trippleWES.SboxInv[decrypted[1][x]] ^ k
                }
                // TEST ME WITH 4
                for ll = 0; ll < 256; ll++ {
                    for x := 0; x < 12; x++ {
                        decrypted[3][x] = trippleWES.SboxInv[trippleWES.SboxInv[decrypted[2][x]] ^ l]
                    }

                    keys[decrypted[3][0]][decrypted[3][1]][decrypted[3][2]][decrypted[3][3]] = append(keys[decrypted[3][0]][decrypted[3][1]][decrypted[3][2]][decrypted[3][3]], keyEntry{ [4]uint8{i,j,k,l}, [8]uint8{decrypted[3][4], decrypted[3][5], decrypted[3][6], decrypted[3][7], decrypted[3][8], decrypted[3][9], decrypted[3][10], decrypted[3][11] } })

                    l++
                }
                k++
            }
            j++
        }
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

    var i,j,k,l,m,n uint8
    var ii, jj, kk, ll, mm, nn int
    var enc [6][12]uint8

    i,j,k,l,m, n = uint8(start), uint8(0), uint8(0), uint8(0), uint8(0), uint8(0)

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

                        for nn = 0; nn < 256; nn++ { // 256*4294967296*(end-start) times -- four billion
                            for x := 0; x < 12; x++ {
                                enc[5][x] = trippleWES.Sbox[enc[4][x]] ^ n
                            }

                            for _, key := range keys[enc[5][0]][enc[5][1]][enc[5][2]][enc[5][3]] {
                                if testGoodKey(&enc[5], &key) {
                                    fmt.Println("\n\n\n FOUNDKEY \n\n\n")
                                    fmt.Printf("Found key: %8b %8b %8b %8b %8b %8b %8b %8b %8b %8b \n", i,j,k,l,m,n,key.Key[0],key.Key[1],key.Key[2],key.Key[3])
                                    fmt.Printf("         = %v  %v  %v  %v  %v  %v  %v  %v  %v  %v \n",  i,j,k,l,m,n,key.Key[0],key.Key[1],key.Key[2],key.Key[3])
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
            if (j+1)%16 == 0 {
                fmt.Printf(" (#%v.%v) ",i,j)
            }
            j++
        }
        fmt.Printf("\nFinished level 1 (#%v)round breaking keys\n",i)
        i++
    }

    // Finished!
    ch <- id
}

func testGoodKey(encrypted *[12]uint8, keyEntry *keyEntry) (bool) {
    // 0, 1 and 2 already match; skip checking those!
    for x := 0; x < 8; x++ {
        if keyEntry.DecryptedValues[x] != encrypted[x + 4] {
            return false
        }
    }

    return true
}
