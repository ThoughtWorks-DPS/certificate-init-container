# certificate-init-container

Variation of the Hightower certificate-init-container.  

Goal is to provide a general purpose init container than can provide tls certificates at time of deployment; self-signed, signed by the internal kubernetes CA, or potentially from an additional number of implemented providers.  

