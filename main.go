package main

// go build -o "Gold cracker mediumDict GCC O3" -compiler gccgo -gccgoflags '-static -O3' main.go
// goxc -n="Gold cracker mediumDict" -os="linux" -arch="amd64"

import(
    "github.com/bcleenders/security_challenge/cracker"
    // "flag"
    "fmt"
    "runtime"
)

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    fmt.Printf("Starting on %v cores.\n", runtime.NumCPU())

    // var start int
    // var end int

    // flag.IntVar(&start, "start", 0, "start value for the cracker (inclusive) default is 0")
    // flag.IntVar(&end, "end", 256, "end value for the cracker (not inclusive) default is 0, max is 256")
    // flag.Parse()
    // end = end % 257

    plaintext := [12]uint8{
        0x41, 0x42, 0x43,
        0x44, 0x45, 0x46,
        0x47, 0x48, 0x49,
        0x4a, 0x4b, 0x4c,
    }

    ciphertext := [12]uint8{
        0x43, 0x10, 0xf7, 0x76,
        0xd6, 0x6c, 0x0c, 0x29,
        0x97, 0x37, 0xe7, 0x98,
    }

    // fmt.Printf("Start cracking from i=%v to i=%v\n", start, end)
    cracker.Crack(plaintext, ciphertext, runtime.NumCPU())
}
