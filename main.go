package main

// go build -o "Gold cracker mediumDict GCC O3" -compiler gccgo -gccgoflags '-static -O3' main.go
// goxc -n="Gold cracker mediumDict" -os="linux" -arch="amd64"

import(
    "github.com/bcleenders/security_challenge/cracker"
    "flag"
    "fmt"
    "runtime"
)

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    fmt.Printf("Starting on %v cores.\n", runtime.NumCPU())

    var start int
    var end int
    var memSteps int

    flag.IntVar(&start, "start", 0, "start value for the cracker (inclusive) default is 0")
    flag.IntVar(&end, "end", 256, "end value for the cracker (not inclusive) default is 0, max is 256")
    flag.Parse()
    end = end % 257

    plaintext := [12]uint8{
        0x41, 0x42, 0x43,
        0x44, 0x45, 0x46,
        0x47, 0x48, 0x49,
        0x4a, 0x4b, 0x4c,
    }

    // ciphertext := [12]uint8{
    //     0x13, 0x2c, 0xf1, 0xa4, 
    //     0xdc, 0xfa, 0xdb, 0x6d, 
    //     0x49, 0x9a, 0x58, 0x91, 
    // }

    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    // TEST VALUE
    ciphertext := [12]uint8{135, 231, 33, 121, 248, 255, 38, 28, 176, 106, 77, 31, }
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")
    fmt.Println("WARNING !!! NOT REAL KEY VALUES!!!!!!!!!!!!!!!!")

    fmt.Printf("Start cracking from i=%v to i=%v\n", start, end)
    cracker.Crack(plaintext, ciphertext, start, end, runtime.NumCPU())
}
