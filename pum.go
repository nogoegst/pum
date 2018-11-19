// pum.go - passphrase unmanager.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of pum, using the creative
// commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package main

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/nogoegst/balloon"
	"github.com/nogoegst/blake2xb"
	"github.com/nogoegst/terminal"
	"golang.org/x/crypto/blake2b"
)

var (
	sCost         = 1 << 21 // 8 MiB
	tCost         = 2
	hashPerson, _ = hex.DecodeString("c1b218d9ae436e38785c0f8595b13959")
	hashSalt, _   = hex.DecodeString("5fa476cbb4293eab784c96fc0f30d529")
)

func KeyDerivationReader(xoflen uint32, passphrase, salt []byte) (io.Reader, error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}
	secret := balloon.Balloon(h, passphrase, salt, uint64(sCost/h.Size()), uint64(tCost))
	b2Config := blake2xb.NewConfig(xoflen)
	b2Config.Salt = hashSalt
	b2Config.Person = hashPerson
	b2xb, err := blake2xb.NewWithConfig(b2Config)
	if err != nil {
		return nil, err
	}
	b2xb.Write(secret)

	return b2xb, nil
}

func DeriveKeymaterial(l uint32, passphrase, salt []byte) ([]byte, error) {
	km := make([]byte, l)
	krd, err := KeyDerivationReader(l, passphrase, salt)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(krd, km)
	if err != nil {
		return nil, err
	}
	return km, nil
}

func main() {
	var outSizeFlag = flag.Int("n", 16, "Bytesize of the output")
	var newPasswordFlag = flag.Bool("new", false, "This is a new password and has to be double-checked")
	flag.Parse()
	outSize := uint32(*outSizeFlag)
	if len(flag.Args()) > 1 {
		log.Fatal("Too many arguments")
	}
	salt := []byte(strings.Join(flag.Args(), ""))
	fmt.Printf("passphrase: ")
	pp, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	if *newPasswordFlag {
		fmt.Printf("repeat passphrase: ")
		pp2, err := terminal.ReadPassword(0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println()
		if subtle.ConstantTimeCompare(pp2, pp) != 1 {
			log.Fatal("Passphrases do not match")
		}
	}
	key, err := DeriveKeymaterial(outSize, pp, salt)
	if err != nil {
		log.Fatal(err)
	}
	out := strings.TrimRight(strings.ToLower(base32.StdEncoding.EncodeToString(key)), "=")
	fmt.Printf("%s\n", out)
}
