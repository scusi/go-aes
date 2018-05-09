package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/nicholastoddsmith/aesrw"
	"io"
	"log"
	"os"
	//"gopkg.in/yaml.v2"
)

var key string
var action string
var out string

func init() {
	flag.Usage = printUsage
	flag.StringVar(&key, "k", "", "key to be used as base64 url encoded string")
	flag.StringVar(&action, "a", "", "action: (e)ncrypt, (d)ecrypt")
	flag.StringVar(&out, "o", "", "file to write output to")
}

func printUsage() {
	fmt.Printf("Usage to %s:\n", os.Args[0])
	fmt.Println("")
	fmt.Println(" aes -a (e|d) [options] [file]")
	fmt.Println("")
	fmt.Println("Note:")
	fmt.Println("- If no file is given stadard input will be used to read data from.")
	fmt.Println("- If no output file is given stadard output will be used to write data to.")

	fmt.Println("- the action option is mandentory")
	fmt.Println("- in case of 'decryption' the key flag (k) is mandentory")
	fmt.Println("")
	fmt.Println("Usage Examples:")
	fmt.Println("===============")
	fmt.Println("")
	fmt.Println("// encyrpt file 'myfile', with a new random key and write to file 'out.aes'")
	fmt.Println("    aes -a e -o out.aes myfile")
	fmt.Println("")
	fmt.Println("Note: if you omit the '-k' key flag a new random key will be generated your you.")
	fmt.Println("      The generated key will be printed out on standard error")

	fmt.Println("")
	fmt.Println("// encyrpt file 'myfile', with a new random key and write to file 'out.aes'")
	fmt.Println("   cat myfile | aes -a e -o out.aes")
	fmt.Println("")

	fmt.Println("// decrypt file 'out.aes', with given key and write cleartext to 'myfile.copy'")
	fmt.Println("   aes -a d -o myfile.copy -k isTll4ijS5lSOWouDHgBo2j9VOXub1iXoUBbiNcmWzQ= out.aes")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("========")
	flag.PrintDefaults()

}

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

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

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
	r := openStdinOrFile()
	//readSomething(r)
	if action == "d" && key == "" {
		err := fmt.Errorf("no key given, decryption needs a key, use -k switch")
		checkFatal(err)
	}
	if action == "e" && key == "" {
		key = genKeyString()
	}
	k, err := base64.URLEncoding.DecodeString(key)
	checkFatal(err)
	switch action {
	case "e":
		// encrypt a file
		var aw *aesrw.AESWriter
		if out != "" {
			f, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE, 0755)
			checkFatal(err)
			aw, err = aesrw.NewWriter(f, k)
		} else {
			aw, err = aesrw.NewWriter(os.Stdout, k)
			checkFatal(err)
		}
		n, err := io.Copy(aw, r)
		checkFatal(err)
		aw.Close()
		log.Printf("%d bytes copied to aes writer\n", n)
	case "d":
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
	}
}
