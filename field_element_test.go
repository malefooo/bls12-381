package bls12381

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestFieldElementValidation(t *testing.T) {
	// Fe
	zero := new(Fe).zero()
	if !zero.isValid() {
		t.Fatal("zero must be valid")
	}
	one := new(Fe).one()
	if !one.isValid() {
		t.Fatal("one must be valid")
	}
	if modulus.isValid() {
		t.Fatal("modulus must be invalid")
	}
	n := modulus.big()
	n.Add(n, big.NewInt(1))
	if new(Fe).setBig(n).isValid() {
		t.Fatal("number greater than modulus must be invalid")
	}
}

func TestFieldElementEquality(t *testing.T) {
	// Fe
	zero := new(Fe).zero()
	if !zero.equal(zero) {
		t.Fatal("0 == 0")
	}
	one := new(Fe).one()
	if !one.equal(one) {
		t.Fatal("1 == 1")
	}
	a, _ := new(Fe).rand(rand.Reader)
	if !a.equal(a) {
		t.Fatal("a == a")
	}
	b := new(Fe)
	add(b, a, one)
	if a.equal(b) {
		t.Fatal("a != a + 1")
	}
	// fe2
	zero2 := new(fe2).zero()
	if !zero2.equal(zero2) {
		t.Fatal("0 == 0")
	}
	one2 := new(fe2).one()
	if !one2.equal(one2) {
		t.Fatal("1 == 1")
	}
	a2, _ := new(fe2).rand(rand.Reader)
	if !a2.equal(a2) {
		t.Fatal("a == a")
	}
	b2 := new(fe2)
	fp2Add(b2, a2, one2)
	if a2.equal(b2) {
		t.Fatal("a != a + 1")
	}
	// fe6
	zero6 := new(fe6).zero()
	if !zero6.equal(zero6) {
		t.Fatal("0 == 0")
	}
	one6 := new(fe6).one()
	if !one6.equal(one6) {
		t.Fatal("1 == 1")
	}
	a6, _ := new(fe6).rand(rand.Reader)
	if !a6.equal(a6) {
		t.Fatal("a == a")
	}
	b6 := new(fe6)
	fp6Add(b6, a6, one6)
	if a6.equal(b6) {
		t.Fatal("a != a + 1")
	}
	// fe12
	zero12 := new(fe12).zero()
	if !zero12.equal(zero12) {
		t.Fatal("0 == 0")
	}
	one12 := new(fe12).one()
	if !one12.equal(one12) {
		t.Fatal("1 == 1")
	}
	a12, _ := new(fe12).rand(rand.Reader)
	if !a12.equal(a12) {
		t.Fatal("a == a")
	}
	b12 := new(fe12)
	fp12Add(b12, a12, one12)
	if a12.equal(b12) {
		t.Fatal("a != a + 1")
	}

}

func TestFieldElementHelpers(t *testing.T) {
	// Fe
	zero := new(Fe).zero()
	if !zero.isZero() {
		t.Fatal("'zero' is not zero")
	}
	one := new(Fe).one()
	if !one.isOne() {
		t.Fatal("'one' is not one")
	}
	odd := new(Fe).setBig(big.NewInt(1))
	if !odd.isOdd() {
		t.Fatal("1 must be odd")
	}
	if odd.isEven() {
		t.Fatal("1 must not be even")
	}
	even := new(Fe).setBig(big.NewInt(2))
	if !even.isEven() {
		t.Fatal("2 must be even")
	}
	if even.isOdd() {
		t.Fatal("2 must not be odd")
	}
	// fe2
	zero2 := new(fe2).zero()
	if !zero2.isZero() {
		t.Fatal("'zero' is not zero, 2")
	}
	one2 := new(fe2).one()
	if !one2.isOne() {
		t.Fatal("'one' is not one, 2")
	}
	// fe6
	zero6 := new(fe6).zero()
	if !zero6.isZero() {
		t.Fatal("'zero' is not zero, 6")
	}
	one6 := new(fe6).one()
	if !one6.isOne() {
		t.Fatal("'one' is not one, 6")
	}
	// fe12
	zero12 := new(fe12).zero()
	if !zero12.isZero() {
		t.Fatal("'zero' is not zero, 12")
	}
	one12 := new(fe12).one()
	if !one12.isOne() {
		t.Fatal("'one' is not one, 12")
	}
}

func TestFieldElementSerialization(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		in := make([]byte, fpByteSize)
		Fe := new(Fe).setBytes(in)
		if !Fe.isZero() {
			t.Fatal("serialization failed")
		}
		if !bytes.Equal(in, Fe.bytes()) {
			t.Fatal("serialization failed")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		for i := 0; i < fuz; i++ {
			a, _ := new(Fe).rand(rand.Reader)
			b := new(Fe).setBytes(a.bytes())
			if !a.equal(b) {
				t.Fatal("serialization failed")
			}
		}
	})
	t.Run("big", func(t *testing.T) {
		for i := 0; i < fuz; i++ {
			a, _ := new(Fe).rand(rand.Reader)
			b := new(Fe).setBig(a.big())
			if !a.equal(b) {
				t.Fatal("encoding or decoding failed")
			}
		}
	})
	t.Run("string", func(t *testing.T) {
		for i := 0; i < fuz; i++ {
			a, _ := new(Fe).rand(rand.Reader)
			b, err := new(Fe).setString(a.string())
			if err != nil {
				t.Fatal(err)
			}
			if !a.equal(b) {
				t.Fatal("encoding or decoding failed")
			}
		}
	})
}

func TestFieldElementByteInputs(t *testing.T) {
	zero := new(Fe).zero()
	in := make([]byte, 0)
	a := new(Fe).setBytes(in)
	if !a.equal(zero) {
		t.Fatal("serialization failed")
	}
	in = make([]byte, fpByteSize)
	a = new(Fe).setBytes(in)
	if !a.equal(zero) {
		t.Fatal("serialization failed")
	}
	in = make([]byte, fpByteSize+200)
	a = new(Fe).setBytes(in)
	if !a.equal(zero) {
		t.Fatal("serialization failed")
	}
	in = make([]byte, fpByteSize+1)
	in[fpByteSize-1] = 1
	normalOne := &Fe{1, 0, 0, 0, 0, 0}
	a = new(Fe).setBytes(in)
	if !a.equal(normalOne) {
		t.Fatal("serialization failed")
	}
}

func TestFieldElementCopy(t *testing.T) {
	a, _ := new(Fe).rand(rand.Reader)
	b := new(Fe).set(a)
	if !a.equal(b) {
		t.Fatal("copy failed")
	}
	a2, _ := new(fe2).rand(rand.Reader)
	b2 := new(fe2).set(a2)
	if !a2.equal(b2) {
		t.Fatal("copy failed")
	}
	a6, _ := new(fe6).rand(rand.Reader)
	b6 := new(fe6).set(a6)
	if !a6.equal(b6) {
		t.Fatal("copy failed")
	}
	a12, _ := new(fe12).rand(rand.Reader)
	b12 := new(fe12).set(a12)
	if !a12.equal(b12) {
		t.Fatal("copy failed2")
	}
}
