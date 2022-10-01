package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/rs/zerolog"
	"github.com/rs/xid"
	"encoding/pem"
	"fmt"
	"strings"
	"path"
	"math/big"
	"os"
	"time"
	"flag"
)

var (
	commonName          string
	organization				string
	organizationalUnit  string
	country							string
	province						string
	locality            string  
	streetAddress				string
	postalCode					string
	caDuration					int
	additionalDNSNames  string
	serviceNames        string
	hostname            string
	subdomain           string
	namespace           string
	clusterDomain     	string
	certDir 						string
	log									zerolog.Logger
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
	flag.IntVar(&caDuration, "ca-duration", 3, "number of years duration of the self-signed CA certificate, default 10")
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&serviceNames, "service-names", "", "service names that resolve to this Pod; comma separated")
	flag.StringVar(&hostname, "hostname", "", "hostname as defined by pod.spec.hostname")
	flag.StringVar(&subdomain, "subdomain", "", "subdomain as defined by pod.spec.subdomain")
	flag.StringVar(&namespace, "namespace", "", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&certDir, "cert-dir", "/etc/tls", "The directory where the TLS certs should be written")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log = zerolog.New(os.Stdout).With().Str("correlationID", xid.New().String()).Str("container", "certificate-init-container").Str("common name", commonName).Timestamp().Logger()
	
	log.Info().Msg("Requested self-signed certificate")
	log.Info().Str("--commonName=", commonName).Send()
	log.Info().Str("--organization=", organization).Send()
	log.Info().Str("--organizationalUnit=", organizationalUnit).Send()
	log.Info().Str("--country=", country).Send()
	log.Info().Str("--province=", province).Send()
	log.Info().Str("--locality=", locality).Send()
	log.Info().Str("--streetAddress=", streetAddress).Send()
	log.Info().Str("--postalCode=", postalCode).Send()
	log.Info().Str("--additionalDNSNames=", additionalDNSNames).Send()
	log.Info().Str("--service-names=",serviceNames).Send()
	log.Info().Str("--hostname=",hostname).Send()
	log.Info().Str("--subdomain=",subdomain).Send()
	log.Info().Str("--namespace=",namespace).Send()
	log.Info().Str("--clusterdomain=",clusterDomain).Send()
	log.Info().Int("--ca-duration=",caDuration).Send()
	log.Info().Str("--cert-dir=",certDir).Send()

	dnsNames := getDNSNames(additionalDNSNames, serviceNames, hostname, subdomain, namespace, clusterDomain)
	log.Info().Str("DNS Names: ", fmt.Sprint(dnsNames)).Send()

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
		log.Fatal().Err(err).Msg("failed to generate CA private key")
	}

	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to generate private key to be signed")
	}

	// create certificate, signing with the CA private key
	certificate, err := x509.CreateCertificate(rand.Reader, cert, ca, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create signed private key")
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
	err = os.MkdirAll(certDir, 0666)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create folder in emptyDir")
	}

	certificatePEMFile := path.Join(certDir, "tls.crt")
	if err := os.WriteFile(certificatePEMFile, certificatePEM.Bytes(), 0644); err != nil {
		log.Fatal().Err(err).Msg("unable to write private certificate to emptyDir")
	}

	privateKeyPEMFile := path.Join(certDir, "tls.key")
	if err := os.WriteFile(privateKeyPEMFile, privateKeyPEM.Bytes(), 0644); err != nil {
		log.Fatal().Err(err).Msg("unable to write private key to emptyDir")
	}
	log.Info().Msg("Success: certificate and private key created")
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
	log.Info().Str("service-domain-name: ", fmt.Sprintf("%s.%s.%s", name, namespace, domain)).Send()
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
}


func podHeadlessDomainName(hostname, subdomain, namespace, domain string) string {
	if hostname == "" || subdomain == "" {
		return ""
	}
	log.Info().Str("pod-headless-domain-name: ", fmt.Sprintf("%s.%s.%s.%s", hostname, subdomain, namespace, domain)).Send()
	return fmt.Sprintf("%s.%s.%s.svc.%s", hostname, subdomain, namespace, domain)
}
