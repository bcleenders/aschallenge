package main

/*
go build -compiler gccgo main.go
go build -o altair -compiler gccgo -gccgoflags '-static' main.go
*/

import(
    "github.com/bcleenders/security_challenge/cracker"
    "runtime"
)

func main() {

    runtime.GOMAXPROCS(4)

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

    cracker.Crack(plaintext, ciphertext)
}
