package main

import(
    "github.com/bcleenders/security_challenge/cracker"
    "flag"
    "fmt"
)

func main() {
    var start int
    var end int

    flag.IntVar(&start, "start", 0, "start value for the cracker (inclusive) default is 0")
    flag.IntVar(&end, "end", 256, "end value for the cracker (not inclusive) default is 0, max is 256")
    flag.Parse()
    end = end % 256

    plaintext := [12]uint8{
        0x41, 0x42, 0x43,
        0x44, 0x45, 0x46,
        0x47, 0x48, 0x49,
        0x4a, 0x4b, 0x4c,
    }

    ciphertext := [12]uint8{
        0x51, 0xc4, 0x8e,
        0xcb, 0xd0, 0xa0,
        0xe8, 0x88, 0xe4,
        0x9e, 0xf5, 0x3b,
    }

    fmt.Printf("Start cracking from i=%v to i=%v\n", start, end)
    cracker.Crack(plaintext, ciphertext, start, end)
}
