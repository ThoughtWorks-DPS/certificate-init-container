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
	"strconv"
	"path"
	"math/big"
	"os"
	"time"
	"flag"
	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"context"
	"k8s.io/client-go/kubernetes"
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
	createSecret				bool
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
	flag.BoolVar(&createSecret, "create-secret", false, "Create kubernetes secret from certificate and private key data")
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
	log.Info().Str("--create-secret=", strconv.FormatBool(createSecret)).Send()

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

	// create kubernetes Secret with certificate and private key data, if requested
	if createSecret {
		log.Info().Msg("create kubernetes secret with certificate and private key data")
		secretData := map[string][]byte{
			"tls.crt": certificatePEM.Bytes(),
			"tls.key": privateKeyPEM.Bytes(),
		}
		secretName := serviceNames + "-certificate"
		certificateSecret := coreV1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			},
			Data: secretData,
		}
	
		// create kubernetes api client
		config := ctrl.GetConfigOrDie()
		kubeClient, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to set go-client")
		}
		// fetch the list of existing secrets in the namespace
		NSSecretList, err := kubeClient.CoreV1().Secrets(namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Fatal().Err(err).Msg("failed to create secret")
		}
		// if the requested secret already exists, get the ResourceVersion so it can be updated
		certificateSecret.ObjectMeta.ResourceVersion = secretExists(NSSecretList, secretName)
	
		// create, or update if already exists
		if certificateSecret.ObjectMeta.ResourceVersion != "" {
			if _, err = kubeClient.CoreV1().Secrets(namespace).Update(context.Background(), &certificateSecret, metav1.UpdateOptions{}); err != nil {
				log.Fatal().Err(err).Msg("failed to update secret")
			}
			log.Info().Msg("Success: updated certificate secret")
		} else {
			if _, err = kubeClient.CoreV1().Secrets(namespace).Create(context.Background(), &certificateSecret, metav1.CreateOptions{}); err != nil {
				log.Fatal().Err(err).Msg("failed to create secret")
			}
			log.Info().Msg("Success: created certificate secret")
		}
	}
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

// search list of existing namespace secrets for match
func secretExists(currentNSSecrets *coreV1.SecretList, secretName string) string {
	log.Info().Str("checking if secret already exists: ", secretName)
	for i := range currentNSSecrets.Items {
		log.Trace().Str("searching:", currentNSSecrets.Items[i].ObjectMeta.Name)
		if currentNSSecrets.Items[i].ObjectMeta.Name == secretName {
			log.Info().Msg("found, update with ResourceVersion")
			return currentNSSecrets.Items[i].ObjectMeta.ResourceVersion
		}
	}
	log.Info().Msg("not found, create new certificate secret")
	return ""
}