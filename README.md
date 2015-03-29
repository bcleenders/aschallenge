# What's this?
This repository contains a bit of (very ugly; it's about the first Go I wrote) Go code that cracks a purely academic cipher.
The workings of the cipher are similar to DES-2 (which is never used: you use either DES or triple DES, *never* double DES).

The cracker exploits a weakness where you attack a cipher from two sides. In this case, it reduces an 80-bit key to two 40-bit keys (i.e. a single 41-bit key). The original 80-bit key is pretty uncrackable, but the 40 bit keys are relatively easily crackable. All you need is some processing power and lots of RAM.

It's written purely as an academic exercise, not for any other people to use. Feel free to use the code (under the MIT license), but don't expect any user-friendly features.

(ofcourse, you're not allowed to hand this in as your own homework -_- but that's basic knowledge...)
