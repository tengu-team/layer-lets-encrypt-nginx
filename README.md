# SSL Termination Proxy

This charm installs an [HTTPS reverse proxy](https://en.wikipedia.org/wiki/TLS_termination_proxy).
The proxy functions as an entrypoint for an entire model. By the use of [subordinate charms](https://github.com/tengu-team/layer-ssl-termination-client), multiple webservices can be connected, each with their own set of domain names and basic_auth data. It also provides loadbalancing per webservice, configured for each webservice, this by the subordinate charms.

The proxy secures traffic to a webservice in the private network using a Let's Encrypt HTTPS certificate.

<img src="https://raw.githubusercontent.com/tengu-team/layer-ssl-termination-proxy/master/docs/ssl-termination-proxy.png">

This proxy receives an A+ rating on the [Qualis SSL Server Test](https://www.ssllabs.com/ssltest/index.html).

# How to use

**HTTPS proxy**

```bash
# Deploy your http webservice.
juju deploy jenkins
# Deploy your proxy-client
juju deploy cs:~tengu-team/ssl-termination-client ssl-jenkins
# Deploy the Proxy.
juju deploy cs:~tengu-team/ssl-termination-proxy
# Expose the proxy.
juju expose ssl-termination-proxy
# Configure your DNS server to point to the ssl-termination-proxy's public ip.
# Let the proxy know what its DNS name is.
# (See https://www.duckdns.org for free DNS names)
# Configure your ssl-client with the webservice-specific configs
# For more detail, see the https://github.com/tengu-team/layer-ssl-termination-client
juju config ssl-jenkins fqdns="example.com www.example.com"
# Connect the webservice with the ssl client
juju add-relation jenkins ssl-jenkins
# Connect the ssl-client with the proxy.
juju add-relation ssl-jenkins:ssltermination ssl-termination-proxy:ssltermination
# Now you can surf to https://example.com and you wil reach the webservice.
```

***OpenStack environments***
If you're using an OpenStack private cloud which uses floating IP addresses, you'll need to associate a floating IP address with the ssl-termination-proxy unit before setting the FQDN, and ensure that this FQDN is reachable from the public Internet.  This is necessary for the Let's Encrypt registration to complete.

*Note: Authentication is turned off for `OPTIONS` requests because this is required for CORS. As part of CORS preflight, `OPTIONS` will get called without authentication headers. If this call fails (with 401 unauthorized), the actual CORS call will not be initiated.*

## Authors

This software was created in the [IBCN research group](https://www.ibcn.intec.ugent.be/) of [Ghent University](https://www.ugent.be/en) in Belgium. This software is used in [Tengu](https://tengu.io), a project that aims to make experimenting with data frameworks and tools as easy as possible.

 - Sander Borny <sander.borny@ugent.be>
 - Merlijn Sebrechts <merlijn.sebrechts@gmail.com>
 - Mathijs Moerman <mathijs.moerman@tengu.io>
