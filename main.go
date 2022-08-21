package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rsa"
	rand "crypto/rand"
  "encoding/pem"
	"math/big"
	"fmt"
	"io/ioutil"
	"path"
	"time"
	"log"
	"flag"
	"net"
	"strings"
)

var (
	additionalDNSNames  string
	commonName          string
	country						 	string
	locality            string  
	organization				string
	organizationalUnit  string
	province						string
	streetAddress				string
	postalCode					string
	clusterDomain     	string
	certDir 					  string
	hostname            string
	namespace           string
	podIP               string
	podName             string
	serviceIPs          string
	serviceNames        string
	subdomain           string
	caDuration					int
)

func main() {
	flag.StringVar(&commonName, "common-name", "", "Common Name for the certificate")
	flag.StringVar(&country, "country", "", "Country for the certificate")
	flag.StringVar(&locality, "locality", "", "Locality for the certificate")
	flag.StringVar(&organization, "organization", "", "Organization for the certificate")
	flag.StringVar(&organizationalUnit, "organizational-unit", "", "Organizational Unit for the certificate")
	flag.StringVar(&province, "province", "", "Province for the certificate")
	flag.StringVar(&streetAddress, "street-address", "", "Street Address for the certificate")
	flag.StringVar(&postalCode, "postal-code", "", "Postal Code for the certificate")
	flag.IntVar(&caDuration, "ca-duration", 10, "number of years duration of the self-signed CA certificate, default 10")
	flag.StringVar(&certDir, "cert-dir", "/etc/tls", "The directory where the TLS certs should be written")
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&hostname, "hostname", "", "hostname as defined by pod.spec.hostname")
	flag.StringVar(&namespace, "namespace", "", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&podIP, "pod-ip", "", "pod ip as defined by pod.status.podIP")
	flag.StringVar(&podName, "pod-name", "", "pod name as defined by pod.metadata.name")
	flag.StringVar(&serviceIPs, "service-ips", "", "service ips as defined by service.spec.clusterIP")
	flag.StringVar(&serviceNames, "service-names", "", "service names that resolve to this Pod; comma separated")
	flag.StringVar(&subdomain, "subdomain", "", "subdomain as defined by pod.spec.subdomain")
	flag.Parse()

	log.Println("self-signed certificate requested with the following information:")
	log.Printf("commonName: %s", commonName)
	log.Printf("country: %s", country)
	log.Printf("locality: %s", locality)
	log.Printf("organization: %s", organization)
	log.Printf("organizationalUnit: %s", organizationalUnit)
	log.Printf("province: %s", province)
	log.Printf("streetAddress: %s", streetAddress)
	log.Printf("postalCode: %s", postalCode)
	log.Printf("clusterdomain: %s",clusterDomain)
	log.Printf("hostname: %s",hostname)
	log.Printf("namespace: %s",namespace)
	log.Printf("service-names: %s",serviceNames)
	log.Printf("subdomain: %s",subdomain)
	log.Printf("ca-duration: %d",caDuration)
	log.Printf("cert-dir: %s",certDir)


	// define the CA
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			CommonName: commonName,
			Organization:  			[]string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:       			[]string{country},
			Province:      			[]string{province},
			Locality:      			[]string{locality},
			StreetAddress: 			[]string{streetAddress},
			PostalCode:    			[]string{postalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caDuration, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// generate the CA private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("failed to generate private key with err %s", err)
	}

	// PEM encode the CA private key
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// write the CA private key to the cert directory
	caTlsKeyFile := path.Join(certDir, "tls.key")
	if err := ioutil.WriteFile(caTlsKeyFile, caPrivKeyPEM.Bytes(), 0644); err != nil {
		log.Fatalf("unable to write to %s: %s", caTlsKeyFile, err)
	}

	// create the CA certificate
	certificate, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Printf("failed to create CA certificate with err %s", err)
	}

	// PEM encode the CA certificate
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})

	// write the CA cert to the cert directory
	caCertFile := path.Join(certDir, "ca.crt")
	if err := ioutil.WriteFile(caCertFile, caPEM.Bytes(), 0644); err != nil {
		log.Fatalf("unable to write to %s: %s", caCertFile, err)
	}

	// log.Printf("CA PEM: %s", caPEM.String())
	// log.Printf("CA Private Key PEM: %s", caPrivKeyPEM.String())

	// define the certificate to be signed
	ipaddresses := getIPs(podIP, serviceIPs)
	dnsNames := getDNSNames(additionalDNSNames, serviceNames, podIP, hostname, subdomain, namespace, clusterDomain)
	log.Printf("IP Addresses: %s", ipaddresses)
	log.Printf("DNS Names: %s", dnsNames)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName: commonName,
			Organization:  			[]string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:       			[]string{country},
			Province:      			[]string{province},
			Locality:      			[]string{locality},
			StreetAddress: 			[]string{streetAddress},
			PostalCode:    			[]string{postalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caDuration, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create private key for the certificate to be signed
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("failed to generate private key for certificate to be signed with err %s", err)
	}

	// create the certificate to be signed
	signedCertificate, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Printf("failed to sign private key for certificate to be signed with err %s", err)
	}

	// PEM encode the signed certificate
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signedCertificate,
	})

	// PEM encode the private key
	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	// write the signed cert to the cert directory
	certCertFile := path.Join(certDir, "tls.crt")
	if err := ioutil.WriteFile(certCertFile, certPEM.Bytes(), 0644); err != nil {
		log.Fatalf("unable to write to %s: %s", certCertFile, err)
	}

	// log.Printf("Certificate PEM: %s", certPEM.String())
	// log.Printf("Certificate Private Key PEM: %s", certPrivKeyPEM.String())

}

func getIPs(podIP, serviceIPs string, ) []net.IP {
	// include parameter passed ips = pod.status.podIP
	ip := net.ParseIP(podIP)
	if ip.To4() == nil && ip.To16() == nil {
		log.Fatal("invalid pod IP address")
	}
	// include localhost
	ipaddresses := []net.IP{ip, net.ParseIP("127.0.0.1")}
	// include serviceIPs
	for _, s := range strings.Split(serviceIPs, ",") {
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip.To4() == nil && ip.To16() == nil {
			log.Fatal("invalid service IP address")
		}
		ipaddresses = append(ipaddresses, ip)
	}

	log.Printf("pod-ips: %s",ipaddresses)
	return ipaddresses
}

func getDNSNames(additionalDNSNames, serviceNames, ip, hostname, subdomain, namespace, clusterDomain string) []string {
	ns := []string{podDomainName(ip, namespace, clusterDomain)}
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

	log.Printf("dns-names: %s",ns)
	return ns
}

func serviceDomainName(name, namespace, domain string) string {
	log.Printf("service-domain-name: %s", fmt.Sprintf("%s.%s.%s", name, namespace, domain))
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
}

func podDomainName(ip, namespace, domain string) string {
	log.Printf("pod-domain-name: %s", fmt.Sprintf("%s.%s.%s", ip, namespace, domain))
	return fmt.Sprintf("%s.%s.pod.%s", strings.Replace(ip, ".", "-", -1), namespace, domain)
}

func podHeadlessDomainName(hostname, subdomain, namespace, domain string) string {
	if hostname == "" || subdomain == "" {
		return ""
	}
	log.Printf("pod-headless-domain-name: %s", fmt.Sprintf("%s.%s.%s.%s", hostname, subdomain, namespace, domain))
	return fmt.Sprintf("%s.%s.%s.svc.%s", hostname, subdomain, namespace, domain)
}