package main

import (
    "fmt"
)

func main() {
    fmt.Println(sboxInv[sbox[11]])
}

/* Add two numbers in a GF(2^8) finite field */
func gadd(a byte, b byte) byte {
    return a ^ b;
}
 
/* Subtract two numbers in a GF(2^8) finite field */
func gsub(a byte, b byte) byte {
    return a ^ b;
}
 
/* Multiply two numbers in the GF(2^8) finite field defined 
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0 */
func gmul(a byte, b byte) byte {
    var p, carry byte = 0, 0

    for i := 0; i < 8; i++ {
        if (b & 1) != 0 {
            p ^= a;
        }
        carry = a & 0x80;  /* detect if x^8 term is about to be generated */
        a <<= 1;
        if carry != 0 {
            a ^= 0x001B; /* replace x^8 with x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

func ginverse(a byte) byte {
    inv := byte(1)
    for j:=0; j<254; j++ {
        inv = gmul(inv, byte(a))
    }

    return inv
}
