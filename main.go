package main

import (
	"bytes"

	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rsa"
	rand "crypto/rand"
  "encoding/pem"
	"math/big"
	//"fmt"
	//"os"
	"time"
	"log"
	"flag"
	"net"
	//"k8s.io/client-go/kubernetes"
	//"k8s.io/client-go/rest"
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
	hostname            string
	namespace           string
	podIP               string
	podName             string
	serviceIPs          string
	serviceNames        string
	subdomain           string
	caDuration					int
	selfSigned          bool    // could make it either use k8s api to sign or completely self-sign
)

func main() {
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&commonName, "common-name", "", "Common Name for the certificate")
	flag.StringVar(&country, "country", "", "Country for the certificate")
	flag.StringVar(&locality, "locality", "", "Locality for the certificate")
	flag.StringVar(&organization, "organization", "", "Organization for the certificate")
	flag.StringVar(&organizationalUnit, "organizational-unit", "", "Organizational Unit for the certificate")
	flag.StringVar(&province, "province", "", "Province for the certificate")
	flag.StringVar(&streetAddress, "street-address", "", "Street Address for the certificate")
	flag.StringVar(&postalCode, "postal-code", "", "Postal Code for the certificate")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&hostname, "hostname", "", "hostname as defined by pod.spec.hostname")
	flag.StringVar(&namespace, "namespace", "", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&podIP, "pod-ip", "", "pod ip as defined by pod.status.podIP")
	flag.StringVar(&podName, "pod-name", "", "pod name as defined by pod.metadata.name")
	flag.StringVar(&serviceIPs, "service-ips", "", "service ips as defined by service.spec.clusterIP")
	flag.StringVar(&serviceNames, "service-names", "", "service names that resolve to this Pod; comma separated")
	flag.StringVar(&subdomain, "subdomain", "", "subdomain as defined by pod.spec.subdomain")
	flag.IntVar(&caDuration, "ca-duration", 10, "number of years duration of the self-signed CA certificate, default 10")
	flag.BoolVar(&selfSigned, "self-signed", false, "whether to self-sign the certificate rather than default k8s CA signature")
	flag.Parse()

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
	log.Printf("self-signed: %t",selfSigned)


	// generate the tls key to be used by the deployment
	tlsKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("unable to genarate the private tls key: %s", err)
	}
	pemTlsKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(tlsKey),
	})

	log.Printf("caPrivKeyPEM: %s", pemTlsKey)

	// create the certificate request
	ipaddresses := getIPs(podIP, serviceIPs)
	dnsNames := getDNSNames(additionalDNSNames, serviceNames, hostname, namespace, podName, subdomain, clusterDomain)
	
  if selfSigned {
		// create the CA certificate

		// CA certificate template
		certificateTemplate := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: commonName,
				Country:    []string{country},
				Locality:   []string{locality},
				Organization: []string{organization},
				OrganizationalUnit: []string{organizationalUnit},
				Province: []string{province},
				StreetAddress: []string{streetAddress},
				PostalCode:  []string{postalCode},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(caDuration,0,0),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		// generate a private key for the CA
		caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Printf("failed with err %s", err)
		}
		// pem encode the CA private key
		caPrivKeyPEM := new(bytes.Buffer)
		pem.Encode(caPrivKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
		})

		// create the CA certificate
		certificate, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &certificateTemplate, &caPrivKey.PublicKey, caPrivKey)
		if err != nil {
			log.Printf("failed with err %s", err)
		}
		// pem encode the CA certificate
		certificatePEM := new(bytes.Buffer)
		pem.Encode(certificatePEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate,
		})

		// generate the certificate for the CA to sign

		log.Printf("certificatePEM: %s", certificatePEM)
	} else {
		// generate a certificate signed by the k8s

	}



	// certificateRequestTemplate := x509.CertificateRequest{
	// 	Subject: pkix.Name{
	// 		CommonName: dnsNames[0],
	// 	},
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// 	DNSNames:           dnsNames,
	// 	IPAddresses:        ipaddresses,
	// }


	// certificateSigningRequestNamwe := "publications-dev-slp"
	// config, err := rest.InClusterConfig()
	// clientset, err := kubernetes.NewForConfig(config)
	// k8s := clientset.CoreV1()


	// csr := &certificates.CertificateSigningRequest{
	// 	ObjectMeta: v1.ObjectMeta{
	// 		Name: "tempcsr",
	// 	},
	// 	Spec: certificates.CertificateSigningRequestSpec{
	// 		Groups: []string{
	// 			"system:authenticated",
	// 		},
	// 		Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes}),
	// 	},
	// }
	// _, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Create(context.TODO(), csr, v1.CreateOptions{})





	// //Create CA
	// ca := &x509.Certificate{
	// 	SerialNumber: big.NewInt(2019),
	// 	Subject: pkix.Name{
	// 		Organization:  []string{"Company, INC."},
	// 		Country:       []string{"US"},
	// 		Province:      []string{""},
	// 		Locality:      []string{"San Francisco"},
	// 		StreetAddress: []string{"Golden Gate Bridge"},
	// 		PostalCode:    []string{"94016"},
	// 	},
	// 	NotBefore:             time.Now(),
	// 	NotAfter:              time.Now().AddDate(3, 0, 0),
	// 	IsCA:                  true,
	// 	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	// 	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	// 	BasicConstraintsValid: true,
	// }



	// // create certificate
	// caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	// if err != nil {
	// 	return err
	// }

	// // pem encode the certificate
	// caPEM := new(bytes.Buffer)
	// pem.Encode(caPEM, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: caBytes,
	// })



	// // create the certificate to be signed
	// cert := &x509.Certificate{
	// 	SerialNumber: big.NewInt(1658),
	// 	Subject: pkix.Name{
	// 		Organization:  []string{"Company, INC."},
	// 		Country:       []string{"US"},
	// 		Province:      []string{""},
	// 		Locality:      []string{"San Francisco"},
	// 		StreetAddress: []string{"Golden Gate Bridge"},
	// 		PostalCode:    []string{"94016"},
	// 	},
	// 	// IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	// 	NotBefore:    time.Now(),
	// 	NotAfter:     time.Now().AddDate(10, 0, 0),
	// 	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	// 	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	// 	KeyUsage:     x509.KeyUsageDigitalSignature,
	// }

	// // create priviate key for the certificate
	// certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	// if err != nil {
	// 	return err
	// }

	// // sign the certificate with the previously created private key
	// certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	// if err != nil {
	// 	return err
	// }

	// // pem encode the certificate and private key
	// certPEM := new(bytes.Buffer)
	// pem.Encode(certPEM, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: certBytes,
	// })

	// certPrivKeyPEM := new(bytes.Buffer)
	// pem.Encode(certPrivKeyPEM, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	// })
}

func getIPs(podIP string, ) []net.IP {
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
	return ipaddresses
}