// go-aes - a commandline tool to apply the AES encryption algorithm on given files.
//
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/nicholastoddsmith/aesrw"
	"io"
	"io/ioutil"
	"log"
	"os"
	//"gopkg.in/yaml.v2"
	"bufio"
	"bytes"
)

// build time variable meant to be filled by goreleaser (or Makefile)
// You can set those also manual like in the below example:
// > go build ldflags="-X main.version={{.Version}} -X main.commit={{.Commit}} -X main.date={{.Date}} -X main.builtBy=goreleaser`" ./cmd/go-aes/
// exchange the placeholders (in curly brackets) with the actual values.
var (
	version   = "dev"
	branch    = "unknown"
	commit    = "unknown"
	date      = "unknown"
	builtBy   = "unknown"
)

var key string
var action string
var out string
var sign bool
var showVersion bool

func init() {
	flag.Usage = printUsage
	flag.StringVar(&key, "k", "", "key to be used as base64 url encoded string")
	flag.StringVar(&action, "a", "", "action: (e)ncrypt, (d)ecrypt, (s)ign, (c)eck signature")
	flag.StringVar(&out, "o", "", "file to write output to")
	flag.BoolVar(&sign, "s", true, "generate HMAC for encrypted file")
	flag.BoolVar(&showVersion, "version", false, "shows version info and exits")
}

func printUsage() {
	fmt.Printf("Usage to %s:\n", os.Args[0])
	fmt.Println("")
	fmt.Println(" go-aes -a (e|d|s|c) [options] [file]")
	fmt.Println("")
	fmt.Println("Note:")
	fmt.Println("- If no file is given stadard input will be used to read data from.")
	fmt.Println("- If no output file is given stadard output will be used to write data to.")
	fmt.Println("- the action option is mandentory")
	fmt.Println("- in case of 'decryption' and 'check signature' the key flag (k) is mandentory")
	fmt.Println("")
	fmt.Println("Usage Examples:")
	fmt.Println("===============")
	fmt.Println("")
	fmt.Println("// encyrpt file 'myfile', with a new random key and write to file 'out.aes'")
	fmt.Println("    go-aes -a e -o out.aes myfile")
	fmt.Println("")
	fmt.Println("Note: if you omit the '-k' key flag a new random key will be generated your you.")
	fmt.Println("      The generated key will be printed out on standard error")

	fmt.Println("")
	fmt.Println("// encyrpt file 'myfile', with a new random key and write to file 'out.aes'")
	fmt.Println("   cat myfile | go-aes -a e -o out.aes")
	fmt.Println("")

	fmt.Println("// decrypt file 'out.aes', with given key and write cleartext to 'myfile.copy'")
	fmt.Println("   go-aes -a d -o myfile.copy -k isTll4ijS5lSOWouDHgBo2j9VOXub1iXoUBbiNcmWzQ= out.aes")
	fmt.Println("")
	fmt.Println("// encrypt a file (with a new random key) but do NOT protect integrity")
	fmt.Println("   go-aes -a e -sign=false myfile")
	fmt.Println("")
	fmt.Println("// protect integrity of a file without encrypting it")
	fmt.Println("   go-aes -a s -k isTll4ijS5lSOWouDHgBo2j9VOXub1iXoUBbiNcmWzQ= -o myfile.signed myfile")
	fmt.Println("")
	fmt.Println("// verify integrity of a file (without decrypting it)")
	fmt.Println("   go-aes -a c -k isTll4ijS5lSOWouDHgBo2j9VOXub1iXoUBbiNcmWzQ= myfile.signed")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("========")
	flag.PrintDefaults()

}

// createMAC - takes a message and a key, returns a HMAC for the given message, with the given key.
// HMAC is 32byte long and based on SHA256
func createMAC(msg, key []byte) (smsg []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	expectedMAC := mac.Sum(nil)
	return []byte(expectedMAC)
}

// checkMAC - takes a message, a HMAC and a key, returns true if the given HMAC is correct.
func checkMAC(msg, msgMac, key []byte) (ans bool) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(msgMac, expectedMAC)
}

// openStdinOrFile - helper function to read from a given file or standard input.
func openStdinOrFile() io.Reader {
	var err error
	r := os.Stdin
	if len(flag.Args()) >= 1 {
		r, err = os.Open(flag.Arg(0))
		if err != nil {
			panic(err)

		}

	}
	return r

}

// checkFatal - Error check routine, throws a fatal error if err is not nil.
func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// genKeyString - helper function to encode a given key into a base64 URL encoded string
func genKeyString() (key string) {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	if err != nil {
		log.Fatal(err)
	}
	key = base64.URLEncoding.EncodeToString(k)
	log.Printf("Key: %s\n", key)
	return key
}

func main() {
	flag.Parse()
	if showVersion {
		fmt.Printf("Version: %s, build by %s, from commit %s at %s", version, builtBy, commit, date)
		os.Exit(0)
	}
	log.Printf("action: %s\n", action)
	log.Printf("sign: %t\n", sign)
	r := openStdinOrFile()
	// if action is 'decryption' and no key was given, throw error and exit.
	if action == "d" && key == "" {
		err := fmt.Errorf("no key given, decryption needs a key, use -k switch")
		checkFatal(err)
	}
	// if action is encryption and no key was given, generate a random key.
	if action == "e" && key == "" {
		key = genKeyString()
	}
	if action == "s" && key == "" {
		key = genKeyString()
	}
	if action == "c" && key == "" {
		key = genKeyString()
		err := fmt.Errorf("no key given, signature checking needs a key, use -k switch")
		checkFatal(err)
	}
	k, err := base64.URLEncoding.DecodeString(key)
	checkFatal(err)
	log.Printf("useing key: %s", key)
	// depending on action...
	switch action {
	case "e": // encrypt a file
		var aw *aesrw.AESWriter
		if out != "" {
			f, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE, 0755)
			checkFatal(err)
			defer f.Close()
			aw, err = aesrw.NewWriter(f, k)
		} else {
			aw, err = aesrw.NewWriter(os.Stdout, k)
			checkFatal(err)
		}
		n, err := io.Copy(aw, r)
		checkFatal(err)
		aw.Close()
		log.Printf("%d bytes copied to aes writer\n", n)
		if sign {
			// sign file with a HMAC
			if out != "" {
				// read output file
				encData, err := ioutil.ReadFile(out)
				// create HMAC
				HMAC := createMAC(encData, k)
				log.Printf("HMAC: %x\n", HMAC)
				// append HMAC to encrypted file
				var signedData bytes.Buffer
				sw := bufio.NewWriter(&signedData)
				sw.Write(encData)
				sw.Write(HMAC)
				sw.Flush()
				// write HMACed encrypted file
				//err = ioutil.WriteFile(out+".signed", signedData.Bytes(), 0755)
				err = ioutil.WriteFile(out, signedData.Bytes(), 0755)
				checkFatal(err)
			} else {
				err := fmt.Errorf("can not sign file, since standard out was used to write data to")
				checkFatal(err)

			}
		}
	case "d":
		if sign {
			// check HMAC
			// read input file
			input, err := ioutil.ReadAll(r)
			checkFatal(err)
			// split HMAC and file
			extractedHMAC := input[len(input)-32:]
			// calculate HMAC for file
			genHMAC := createMAC(input[0:len(input)-32], k)
			// check if extracted HMAC matches calculated HMAC
			if checkMAC(input[0:len(input)-32], extractedHMAC, k) {
				log.Printf("HMAC (%x) is correct.\n", genHMAC)
			} else {
				err := fmt.Errorf("HMAC IS NOT CORRECT, aborting")
				log.Printf("The file was possibly altered in transit, the signature is not correct.")
				checkFatal(err)
			}
			r = bytes.NewReader(input[0 : len(input)-32])
		}
		// decrypt a file
		ar, err := aesrw.NewReader(r, k)
		checkFatal(err)
		var n int64
		if out != "" {
			f, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE, 0755)
			checkFatal(err)
			n, err = io.Copy(f, ar)
			checkFatal(err)
		} else {
			n, err = io.Copy(os.Stdout, ar)
			checkFatal(err)
		}
		log.Printf("%d bytes copied from aes reader\n", n)
	case "s":
		// sign file with a HMAC
		var inBuf bytes.Buffer
		inWriter := bufio.NewWriter(&inBuf)
		io.Copy(inWriter, r)
		inWriter.Flush()
		log.Printf("sign data with key: %s", key)
		HMAC := createMAC(inBuf.Bytes(), k)
		log.Printf("HMAC: %x\n", HMAC)
		inWriter.Write(HMAC)
		inWriter.Flush()
		if out != "" {
			ioutil.WriteFile(out, inBuf.Bytes(), 0755)
		}
	case "c":
		// check HMAC
		// read input file
		input, err := ioutil.ReadAll(r)
		checkFatal(err)
		// split HMAC and file
		extractedHMAC := input[len(input)-32:]
		// calculate HMAC for file
		genHMAC := createMAC(input[0:len(input)-32], k)
		// check if extracted HMAC matches calculated HMAC
		if checkMAC(input[0:len(input)-32], extractedHMAC, k) {
			log.Printf("HMAC (%x) is correct.\n", genHMAC)
		} else {
			log.Printf("HMAC (%x) IS NOT correct!\n", extractedHMAC)
			log.Printf("WARNING: HMAC verification failed!")
		}
		if out != "" {
			ioutil.WriteFile(out, input[0:len(input)-32], 0755)
			fmt.Printf("now decrypt file '%s'\n", out)
		}
	}
}
