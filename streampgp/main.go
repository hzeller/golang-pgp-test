package main

import (
	"crypto"
	"flag"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"log"
	"os"

	_ "crypto/sha256"
	_ "golang.org/x/crypto/ripemd160"
)

func main() {
	encrypt_out := flag.String("out", "ciphertext.out", "Ciphertext")

	log.Println("Create key pair")
	// Create a key-pair
	entity, _ := openpgp.NewEntity("The Receiver", "testing",
		"henner.zeller+testing@gmail.com", nil)

	log.Println("Start encryption")
	config := &packet.Config{
		DefaultHash: crypto.SHA256,
	}
	file, err := os.OpenFile(*encrypt_out, os.O_WRONLY|os.O_CREATE, 0600)

	// For some reason it uses RIPEMD160 ?
	plain, err := openpgp.Encrypt(file, []*openpgp.Entity{entity},
		nil, nil, config)
	if err != nil {
		log.Fatal(err)
	}

	// Input of plaintext: a stream (as we typically would get from a
	// network stream).
	plain.Write([]byte("Hello World plaintext!\n"))
	plain.Close()

	// Decrypt
	read_file, _ := os.Open(*encrypt_out)
	keyring := openpgp.EntityList{entity}

	message, err := openpgp.ReadMessage(read_file, keyring,
		func(keys []openpgp.Key, sym bool) ([]byte, error) {
			log.Printf("Prompt got called\n")
			return nil, nil
		}, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Read the encrypted file and dump plain-text to stdout.
	body_reader := message.UnverifiedBody
	buffer := make([]byte, 1024)
	for {
		n, _ := body_reader.Read(buffer)
		if n == 0 {
			break
		}
		os.Stdout.Write(buffer[0:n])
	}
	log.Println("Done.")
}
