# certificate-init-container

Variation of the Hightower certificate-init-container.  

Goal is to provide a general purpose init container than can provide tls certificates at time of deployment; self-signed, signed by the internal kubernetes CA, or potentially from an additional number of implemented providers.  

```
--common-name opa-injection-admission-controller \
--organization 'Thoughtworks, Inc.' \
--organizational-unit EMPC \
--country USA \
--province Illinois \
--locality Chicago \
--street-address '200 E Randolph St 25th Floor' \
--postal-code 60601 \
--service-names opa-injection-admission-controller \
--namespace opa-system
```