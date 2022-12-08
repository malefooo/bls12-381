package bls12381

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

// Fe is base field element representation
type Fe /***			***/ [fpNumberOfLimbs]uint64

// fe2 is element representation of 'fp2' which is quadratic extention of base field 'fp'
// Representation follows c[0] + c[1] * u encoding order.
type fe2 /**			***/ [2]Fe

// fe6 is element representation of 'fp6' field which is cubic extention of 'fp2'
// Representation follows c[0] + c[1] * v + c[2] * v^2 encoding order.
type fe6 /**			***/ [3]fe2

// fe12 is element representation of 'fp12' field which is quadratic extention of 'fp6'
// Representation follows c[0] + c[1] * w encoding order.
type fe12 /**			***/ [2]fe6

type wfe /***			***/ [fpNumberOfLimbs * 2]uint64
type wfe2 /**			***/ [2]wfe
type wfe6 /**			***/ [3]wfe2

func (Fe *Fe) setBytes(in []byte) *Fe {
	l := len(in)
	if l >= fpByteSize {
		l = fpByteSize
	}
	padded := make([]byte, fpByteSize)
	copy(padded[fpByteSize-l:], in[:])
	var a int
	for i := 0; i < fpNumberOfLimbs; i++ {
		a = fpByteSize - i*8
		Fe[i] = uint64(padded[a-1]) | uint64(padded[a-2])<<8 |
			uint64(padded[a-3])<<16 | uint64(padded[a-4])<<24 |
			uint64(padded[a-5])<<32 | uint64(padded[a-6])<<40 |
			uint64(padded[a-7])<<48 | uint64(padded[a-8])<<56
	}
	return Fe
}

func (Fe *Fe) setBig(a *big.Int) *Fe {
	return Fe.setBytes(a.Bytes())
}

func (Fe *Fe) setString(s string) (*Fe, error) {
	if s[:2] == "0x" {
		s = s[2:]
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return Fe.setBytes(bytes), nil
}

func (Fe *Fe) set(fe2 *Fe) *Fe {
	Fe[0] = fe2[0]
	Fe[1] = fe2[1]
	Fe[2] = fe2[2]
	Fe[3] = fe2[3]
	Fe[4] = fe2[4]
	Fe[5] = fe2[5]
	return Fe
}

func (Fe *Fe) bytes() []byte {
	out := make([]byte, fpByteSize)
	var a int
	for i := 0; i < fpNumberOfLimbs; i++ {
		a = fpByteSize - i*8
		out[a-1] = byte(Fe[i])
		out[a-2] = byte(Fe[i] >> 8)
		out[a-3] = byte(Fe[i] >> 16)
		out[a-4] = byte(Fe[i] >> 24)
		out[a-5] = byte(Fe[i] >> 32)
		out[a-6] = byte(Fe[i] >> 40)
		out[a-7] = byte(Fe[i] >> 48)
		out[a-8] = byte(Fe[i] >> 56)
	}
	return out
}

func (Fe *Fe) big() *big.Int {
	return new(big.Int).SetBytes(Fe.bytes())
}

func (Fe *Fe) string() (s string) {
	for i := fpNumberOfLimbs - 1; i >= 0; i-- {
		s = fmt.Sprintf("%s%16.16x", s, Fe[i])
	}
	return "0x" + s
}

func (Fe *Fe) zero() *Fe {
	Fe[0] = 0
	Fe[1] = 0
	Fe[2] = 0
	Fe[3] = 0
	Fe[4] = 0
	Fe[5] = 0
	return Fe
}

func (Fe *Fe) one() *Fe {
	return Fe.set(r1)
}

func (Fe *Fe) rand(r io.Reader) (*Fe, error) {
	bi, err := rand.Int(r, modulus.big())
	if err != nil {
		return nil, err
	}
	return Fe.setBig(bi), nil
}

func (Fe *Fe) isValid() bool {
	return Fe.cmp(&modulus) == -1
}

func (Fe *Fe) isOdd() bool {
	var mask uint64 = 1
	return Fe[0]&mask != 0
}

func (Fe *Fe) isEven() bool {
	var mask uint64 = 1
	return Fe[0]&mask == 0
}

func (Fe *Fe) isZero() bool {
	return (Fe[5] | Fe[4] | Fe[3] | Fe[2] | Fe[1] | Fe[0]) == 0
}

func (Fe *Fe) isOne() bool {
	return Fe.equal(r1)
}

func (Fe *Fe) cmp(fe2 *Fe) int {
	for i := fpNumberOfLimbs - 1; i >= 0; i-- {
		if Fe[i] > fe2[i] {
			return 1
		} else if Fe[i] < fe2[i] {
			return -1
		}
	}
	return 0
}

func (Fe *Fe) equal(fe2 *Fe) bool {
	return fe2[0] == Fe[0] && fe2[1] == Fe[1] && fe2[2] == Fe[2] && fe2[3] == Fe[3] && fe2[4] == Fe[4] && fe2[5] == Fe[5]
}

func (e *Fe) signBE() bool {
	negZ, z := new(Fe), new(Fe)
	fromMont(z, e)
	neg(negZ, z)
	return negZ.cmp(z) > -1
}

func (e *Fe) sign() bool {
	r := new(Fe)
	fromMont(r, e)
	return r[0]&1 == 0
}

func (e *Fe) div2(u uint64) {
	e[0] = e[0]>>1 | e[1]<<63
	e[1] = e[1]>>1 | e[2]<<63
	e[2] = e[2]>>1 | e[3]<<63
	e[3] = e[3]>>1 | e[4]<<63
	e[4] = e[4]>>1 | e[5]<<63
	e[5] = e[5]>>1 | u<<63
}

func (e *Fe) mul2() uint64 {
	u := e[5] >> 63
	e[5] = e[5]<<1 | e[4]>>63
	e[4] = e[4]<<1 | e[3]>>63
	e[3] = e[3]<<1 | e[2]>>63
	e[2] = e[2]<<1 | e[1]>>63
	e[1] = e[1]<<1 | e[0]>>63
	e[0] = e[0] << 1
	return u
}

func (e *fe2) zero() *fe2 {
	e[0].zero()
	e[1].zero()
	return e
}

func (e *fe2) one() *fe2 {
	e[0].one()
	e[1].zero()
	return e
}

func (e *fe2) set(e2 *fe2) *fe2 {
	e[0].set(&e2[0])
	e[1].set(&e2[1])
	return e
}

func (e *fe2) fromMont(a *fe2) {
	fromMont(&e[0], &a[0])
	fromMont(&e[1], &a[1])
}

func (e *fe2) fromWide(w *wfe2) {
	fromWide(&e[0], &w[0])
	fromWide(&e[1], &w[1])
}

func (e *fe2) rand(r io.Reader) (*fe2, error) {
	a0, err := new(Fe).rand(r)
	if err != nil {
		return nil, err
	}
	e[0].set(a0)
	a1, err := new(Fe).rand(r)
	if err != nil {
		return nil, err
	}
	e[1].set(a1)
	return e, nil
}

func (e *fe2) isOne() bool {
	return e[0].isOne() && e[1].isZero()
}

func (e *fe2) isZero() bool {
	return e[0].isZero() && e[1].isZero()
}

func (e *fe2) equal(e2 *fe2) bool {
	return e[0].equal(&e2[0]) && e[1].equal(&e2[1])
}

func (e *fe2) signBE() bool {
	if !e[1].isZero() {
		return e[1].signBE()
	}
	return e[0].signBE()
}

func (e *fe2) sign() bool {
	r := new(Fe)
	if !e[0].isZero() {
		fromMont(r, &e[0])
		return r[0]&1 == 0
	}
	fromMont(r, &e[1])
	return r[0]&1 == 0
}

func (e *fe6) zero() *fe6 {
	e[0].zero()
	e[1].zero()
	e[2].zero()
	return e
}

func (e *fe6) one() *fe6 {
	e[0].one()
	e[1].zero()
	e[2].zero()
	return e
}

func (e *fe6) set(e2 *fe6) *fe6 {
	e[0].set(&e2[0])
	e[1].set(&e2[1])
	e[2].set(&e2[2])
	return e
}

func (e *fe6) fromMont(a *fe6) {
	e[0].fromMont(&a[0])
	e[1].fromMont(&a[1])
	e[2].fromMont(&a[2])
}

func (e *fe6) fromWide(w *wfe6) {
	e[0].fromWide(&w[0])
	e[1].fromWide(&w[1])
	e[2].fromWide(&w[2])
}

func (e *fe6) rand(r io.Reader) (*fe6, error) {
	a0, err := new(fe2).rand(r)
	if err != nil {
		return nil, err
	}
	e[0].set(a0)
	a1, err := new(fe2).rand(r)
	if err != nil {
		return nil, err
	}
	e[1].set(a1)
	a2, err := new(fe2).rand(r)
	if err != nil {
		return nil, err
	}
	e[2].set(a2)
	return e, nil
}

func (e *fe6) isOne() bool {
	return e[0].isOne() && e[1].isZero() && e[2].isZero()
}

func (e *fe6) isZero() bool {
	return e[0].isZero() && e[1].isZero() && e[2].isZero()
}

func (e *fe6) equal(e2 *fe6) bool {
	return e[0].equal(&e2[0]) && e[1].equal(&e2[1]) && e[2].equal(&e2[2])
}

func (e *fe12) zero() *fe12 {
	e[0].zero()
	e[1].zero()
	return e
}

func (e *fe12) one() *fe12 {
	e[0].one()
	e[1].zero()
	return e
}

func (e *fe12) set(e2 *fe12) *fe12 {
	e[0].set(&e2[0])
	e[1].set(&e2[1])
	return e
}

func (e *fe12) fromMont(a *fe12) {
	e[0].fromMont(&a[0])
	e[1].fromMont(&a[1])
}

func (e *fe12) rand(r io.Reader) (*fe12, error) {
	a0, err := new(fe6).rand(r)
	if err != nil {
		return nil, err
	}
	e[0].set(a0)
	a1, err := new(fe6).rand(r)
	if err != nil {
		return nil, err
	}
	e[1].set(a1)
	return e, nil
}

func (e *fe12) isOne() bool {
	return e[0].isOne() && e[1].isZero()
}

func (e *fe12) isZero() bool {
	return e[0].isZero() && e[1].isZero()
}

func (e *fe12) equal(e2 *fe12) bool {
	return e[0].equal(&e2[0]) && e[1].equal(&e2[1])
}

func (Fe *wfe) set(fe2 *wfe) *wfe {
	Fe[0] = fe2[0]
	Fe[1] = fe2[1]
	Fe[2] = fe2[2]
	Fe[3] = fe2[3]
	Fe[4] = fe2[4]
	Fe[5] = fe2[5]
	Fe[6] = fe2[6]
	Fe[7] = fe2[7]
	Fe[8] = fe2[8]
	Fe[9] = fe2[9]
	Fe[10] = fe2[10]
	Fe[11] = fe2[11]
	return Fe
}

func (Fe *wfe2) set(fe2 *wfe2) *wfe2 {
	Fe[0].set(&fe2[0])
	Fe[1].set(&fe2[1])
	return Fe
}

func (Fe *wfe6) set(fe2 *wfe6) *wfe6 {
	Fe[0].set(&fe2[0])
	Fe[1].set(&fe2[1])
	Fe[2].set(&fe2[2])
	return Fe
}
