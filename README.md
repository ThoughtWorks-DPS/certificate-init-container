<div align="center">
	<p>
		<img alt="Thoughtworks Logo" src="https://raw.githubusercontent.com/ThoughtWorks-DPS/static/master/thoughtworks_flamingo_wave.png?sanitize=true" width=200 />
    <br />
		<img alt="DPS Title" src="https://raw.githubusercontent.com/ThoughtWorks-DPS/static/master/EMPCPlatformStarterKitsImage.png?sanitize=true" width=350/>
	</p>
  <br />
  <h3>certificate-init-container</h3>
    <a href="https://app.circleci.com/pipelines/github/ThoughtWorks-DPS/certificate-init-container"><img src="https://circleci.com/gh/ThoughtWorks-DPS/certificate-init-container.svg?style=shield"></a> <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</div>
<br />

A general purpose init container than can generate self-signed tls certificates for kubernetes pods at time of deployment.  

## Usage

Add the init container to an existing deployment.

```yaml
initContainers:
    - name: certificate-init-container
        image: twdps/certificate-init-container:0.2.0
        imagePullPolicy: Always
        env:
        - name: NAMESPACE                                      # example of how the namespace can be accessed from the environment
            valueFrom:
            fieldRef:
                fieldPath: metadata.namespace
        - name: POD_NAME                                       # example of using pod information from the environment
            valueFrom:
            fieldRef:
                fieldPath: metadata.name
        - name: POD_IP
            valueFrom:
            fieldRef:
                fieldPath: status.podIP
        args:                                                  # not all parameters required
        - "--common-name=twdps.io"                             # use only those parameters necssary to fit your use case
        - "--organization='Thoughtworks, Inc.'"
        - "--organizational-unit=EMPC"
        - "--country=USA"
        - "--province=Illinois"
        - "--locality=Chicago"
        - "--street-address='200 E Randolph St 25th Floor'"
        - "--postal-code=60601"
        - "--ca-duration=3"                                    # default is 3 years
        - "--additional-dnsnames=www.twdps.io"
        - "--service-names=init-container"
        - "--hostname=$(POD_IP)"
        - "--subdomain=$(POD_NAME)"
        - "--namespace=$(NAMESPACE)"
        - "--cluster-domain=cluster.local"                     # default is cluster.local
        - "--cert-dir=/etc/tls"                                # default is /etc/tls 
        volumeMounts:
        - name: tls
            mountPath: /etc/tls
        ...

    # with the tls volumeMount configured to reference the pod shared volume
    # be sure to include in your container definition
    volumes:
        - name: tls
          emptyDir: {}
```

The associated certificate dnsnames are extracted as follows:

* each comma separated item in addition-dnsnames
* each comma separated item in service-names, included as service-name.namespace.cluster-domain
* if both hostname and subdomain are defined, a pod-headless-domain-name is included as hostname.subdomain.namespace.cluster-domain

Use only the parameters necessary to create the desired dns name identifiers.  

At deployment, the certificate-init-container will run first.  

It will generate a new CA certificate and private key based on the parameters provided:
```go
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
```
Then it will generate a new certificate and private key, signed by the above CA, and lastly write PEM encoded versions of the resulting files as tls.crt and tls.key, respectively, to the provided directory path in the pod shared emptyDir volume.  

The other containers in the pod can now access the certificate files and use as needed.  

### Development

To test certificate generation provide a cert directory override to have the files written locally.
```bash
go run main.go -cert-dir=./
```

This is an adaptation of Kelsey Hightower's [certificate-init-container](https://github.com/kelseyhightower/certificate-init-container). _Note: The darwin build is a universal binary for Apple Silicon support._   
