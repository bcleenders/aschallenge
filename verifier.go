package main

import(
    "github.com/bcleenders/security_challenge/trippleWES"
    "fmt"
)

func main() {

    plaintext := [12]uint8{
        0x41, 0x42,
        0x43, 0x44,
        0x45, 0x46,
        0x47, 0x48,
        0x49, 0x4a,
        0x4b, 0x4c,
    }

    ciphertext := [12]uint8{
        0xfd, 0x2f,
        0x1a, 0xcd,
        0x06, 0x8b,
        0x1b, 0xbc,
        0x1e, 0x53,
        0x50, 0xd4,
    }

    key := [10]uint8{
        0,0,0,0,0,
        0,0,0,0,0,
    }

    challengetext := []uint8 {
        0x0f, 0xf6, 0xa3, 0x62,
        0xa5, 0xb5, 0x0f, 0xca,
        0x0f, 0x92, 0x27, 0xca,
        0x13, 0x62, 0x14, 0xbb,
        0xb5, 0xc0, 0xbf, 0x81,
        0xca, 0x89, 0x20, 0x89,
        0xa4, 0x89, 0x89, 0xc7,
        0x89, 0x4b,
    }

    for i := 0; i < len(plaintext); i++ {
        cip := trippleWES.Encrypt(plaintext[i], key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9])
        fmt.Printf("Enc(%v) = %8b (%8b expected)\n", plaintext[i], cip, ciphertext[i])
    }

    for _, v := range challengetext {
        plt := trippleWES.Decrypt(v, key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9])
        fmt.Printf("%v ", plt)
    }
}