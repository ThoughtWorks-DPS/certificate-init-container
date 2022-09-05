package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"path"
	"math/big"
	"os"
	"time"
	"flag"
)

var (
	commonName          string
	organization		string
	organizationalUnit  string
	country				string
	province			string
	locality            string  
	streetAddress		string
	postalCode			string
	caDuration			int
	additionalDNSNames  string
	serviceNames        string
	hostname            string
	subdomain           string
	namespace           string
	clusterDomain     	string
	certDir 			string
)

func main() {
	var certificatePEM, privateKeyPEM *bytes.Buffer

	flag.StringVar(&commonName, "common-name", "", "Common Name for the certificate")
	flag.StringVar(&organization, "organization", "", "Organization for the certificate")
	flag.StringVar(&organizationalUnit, "organizational-unit", "", "Organizational Unit for the certificate")
	flag.StringVar(&country, "country", "", "Country for the certificate")
	flag.StringVar(&province, "province", "", "Province for the certificate")
	flag.StringVar(&locality, "locality", "", "Locality for the certificate")
	flag.StringVar(&streetAddress, "street-address", "", "Street Address for the certificate")
	flag.StringVar(&postalCode, "postal-code", "", "Postal Code for the certificate")
	flag.IntVar(&caDuration, "ca-duration", 10, "number of years duration of the self-signed CA certificate, default 10")
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&serviceNames, "service-names", "", "service names that resolve to this Pod; comma separated")
	flag.StringVar(&hostname, "hostname", "", "hostname as defined by pod.spec.hostname")
	flag.StringVar(&subdomain, "subdomain", "", "subdomain as defined by pod.spec.subdomain")
	flag.StringVar(&namespace, "namespace", "", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&certDir, "cert-dir", "/etc/tls", "The directory where the TLS certs should be written")
	flag.Parse()

	log.Println("self-signed certificate requested with the following information:")
	log.Printf("commonName: %s", commonName)
	log.Printf("organization: %s", organization)
	log.Printf("organizationalUnit: %s", organizationalUnit)
	log.Printf("country: %s", country)
	log.Printf("province: %s", province)
	log.Printf("locality: %s", locality)
	log.Printf("streetAddress: %s", streetAddress)
	log.Printf("postalCode: %s", postalCode)
	log.Printf("additionalDNSNames: %s", additionalDNSNames)
	log.Printf("service-names: %s",serviceNames)
	log.Printf("hostname: %s",hostname)
	log.Printf("subdomain: %s",subdomain)
	log.Printf("namespace: %s",namespace)
	log.Printf("clusterdomain: %s",clusterDomain)
	log.Printf("ca-duration: %d",caDuration)
	log.Printf("cert-dir: %s",certDir)

	dnsNames := getDNSNames(additionalDNSNames, serviceNames, hostname, subdomain, namespace, clusterDomain)
	log.Printf("DNS Names: %s", dnsNames)

	// define the Certificate Authority (CA) certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			CommonName: 		commonName,
			Organization:  		[]string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:       		[]string{country},
			Province:      		[]string{province},
			Locality:      		[]string{locality},
			StreetAddress: 		[]string{streetAddress},
			PostalCode:    		[]string{postalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caDuration, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// define the certficate to be provided via this init container
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:   		commonName,
			Organization:  		[]string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:       		[]string{country},
			Province:      		[]string{province},
			Locality:      		[]string{locality},
			StreetAddress: 		[]string{streetAddress},
			PostalCode:    		[]string{postalCode},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(caDuration, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// generate CA private key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generate CA private key with err %s", err)
	}

	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generate private key to be signed with err %s", err)
	}

	// create certificate, signing with the CA private key
	certificate, err := x509.CreateCertificate(rand.Reader, cert, ca, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("failed to create signed private key with err %s", err)
	}

	// PEM encode the private key and certificate
	certificatePEM = new(bytes.Buffer)
	_ = pem.Encode(certificatePEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})

	privateKeyPEM = new(bytes.Buffer)
	_ = pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// write the signed certificate to the shared pod emptyDir
	certificatePEMFile := path.Join(certDir, "tls.crt")
	if err := os.WriteFile(certificatePEMFile, certificatePEM.Bytes(), 0644); err != nil {
		log.Fatalf("unable to write private certificate to %s: %s", certificatePEMFile, err)
	}

	privateKeyPEMFile := path.Join(certDir, "tls.key")
	if err := os.WriteFile(privateKeyPEMFile, privateKeyPEM.Bytes(), 0644); err != nil {
		log.Fatalf("unable to write private key to %s: %s", privateKeyPEMFile, err)
	}

	// err = os.MkdirAll("/etc/webhook/certs/", 0666)
	// if err != nil {
	// 	log.Panic(err)
	// }
	// err = WriteFile("/etc/webhook/certs/tls.crt", serverCertPEM)
	// if err != nil {
	// 	log.Panic(err)
	// }

	// err = WriteFile("/etc/webhook/certs/tls.key", serverPrivKeyPEM)
	// if err != nil {
	// 	log.Panic(err)
	// }

}

func getDNSNames(additionalDNSNames, serviceNames, hostname, subdomain, namespace, clusterDomain string) []string {
	var ns []string
	if hostname != "" && subdomain != "" {
		ns = append(ns, podHeadlessDomainName(hostname, subdomain, namespace, clusterDomain))
	}

	for _, n := range strings.Split(additionalDNSNames, ",") {
		if n == "" {
			continue
		}
		ns = append(ns, n)
	}

	for _, n := range strings.Split(serviceNames, ",") {
		if n == "" {
			continue
		}
		ns = append(ns, serviceDomainName(n, namespace, clusterDomain))
	}
	return ns
}

func serviceDomainName(name, namespace, domain string) string {
	log.Printf("service-domain-name: %s", fmt.Sprintf("%s.%s.%s", name, namespace, domain))
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
}


func podHeadlessDomainName(hostname, subdomain, namespace, domain string) string {
	if hostname == "" || subdomain == "" {
		return ""
	}
	log.Printf("pod-headless-domain-name: %s", fmt.Sprintf("%s.%s.%s.%s", hostname, subdomain, namespace, domain))
	return fmt.Sprintf("%s.%s.%s.svc.%s", hostname, subdomain, namespace, domain)
}

// WriteFile writes data in the file at the given path
// func WriteFile(filepath string, sCert *bytes.Buffer) error {
// 	f, err := os.Create(filepath)
// 	if err != nil {
// 		return err
// 	}
// 	defer f.Close()

// 	_, err = f.Write(sCert.Bytes())
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
