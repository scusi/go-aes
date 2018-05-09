package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	if err != nil {
		log.Fatal(err)
	}
	key := base64.URLEncoding.EncodeToString(k)
	fmt.Printf("Key: %s\n", key)
}
