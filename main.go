package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/sign"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	// First signature using private key and PFX certificate
	firstSign()

	// Second signature using locally generated private key and self-signed root certificate
	secondSign()
}

func firstSign() {
	// Read PKCS12 (.pfx) file
	p12Data, err := ioutil.ReadFile("./23830612.pfx")
	if err != nil {
		log.Fatal(err)
	}

	// Decode the certificate chain
	key, cert, caCerts, err := pkcs12.DecodeChain(p12Data, "98106279")
	if err != nil {
		log.Fatal(err)
	}

	// Build certChains from cert and caCerts
	var certChains [][]*x509.Certificate
	if len(caCerts) > 0 {
		certChains = append(certChains, append([]*x509.Certificate{cert}, caCerts...))
	} else {
		certChains = append(certChains, []*x509.Certificate{cert})
	}

	// Signing the PDF for the first time
	inputFile, err := os.Open("input.pdf")
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	fileInfo, err := inputFile.Stat()
	if err != nil {
		panic(err)
	}
	size := fileInfo.Size()

	pdfReader, err := pdf.NewReader(inputFile, size)
	if err != nil {
		panic(err)
	}

	outputFile, err := os.Create("output_first_signed.pdf")
	if err != nil {
		panic(err)
	}
	defer outputFile.Close()

	err = sign.Sign(inputFile, outputFile, pdfReader, size, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "WILLIAN SANTANA",
				Location:    "Your location",
				Reason:      "Your reason",
				ContactInfo: "Your contact info",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            key.(crypto.Signer),
		DigestAlgorithm:   crypto.SHA256,
		Certificate:       cert,
		CertificateChains: certChains,
		TSA: sign.TSA{
			URL:      "",
			Username: "",
			Password: "",
		},
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
	})

	if err != nil {
		log.Println(err)
	} else {
		log.Println("First subscription completed successfully")
	}
}

func secondSign() {
	// Generate a private key and self-signed root certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	x509RootCertificate := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Organization:  []string{"Your Organization"},
			Country:       []string{"Your Country"},
			Province:      []string{"Your Province"},
			Locality:      []string{"Your Locality"},
			StreetAddress: []string{"Your Street Address"},
			PostalCode:    []string{"Your Postal Code"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	rootCertificateBytes, err := x509.CreateCertificate(rand.Reader, x509RootCertificate, x509RootCertificate, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	rootCertificate, err := x509.ParseCertificate(rootCertificateBytes)
	if err != nil {
		panic(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)

	certificateChain, err := rootCertificate.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		panic(err)
	}

	// Reopen the PDF signed in the first step
	inputFile, err := os.Open("output_first_signed.pdf")
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	fileInfo, err := inputFile.Stat()
	if err != nil {
		panic(err)
	}
	size := fileInfo.Size()

	pdfReader, err := pdf.NewReader(inputFile, size)
	if err != nil {
		panic(err)
	}

	// Sign the PDF again
	outputFile, err := os.Create("output_final_signed.pdf")
	if err != nil {
		panic(err)
	}
	defer outputFile.Close()

	err = sign.Sign(inputFile, outputFile, pdfReader, size, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "Your Second Signature",
				Location:    "Another location",
				Reason:      "Second signature reason",
				ContactInfo: "Another contact info",
				Date:        time.Now().Local(),
			},
			CertType:   sign.CertificationSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            privateKey, // Signer using locally generated private key
		DigestAlgorithm:   crypto.SHA256,
		Certificate:       rootCertificate,
		CertificateChains: certificateChain,
		TSA: sign.TSA{
			URL:      "",
			Username: "",
			Password: "",
		},
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
	})

	if err != nil {
		log.Println(err)
	} else {
		log.Println("Second subscription completed successfully")
	}
}
