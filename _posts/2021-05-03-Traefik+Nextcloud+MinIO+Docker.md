---
title:  "Traefik+Nextcloud+Step-ca+Docker"
layout: post
---

Today I wanted to make a small post about how to deploy your Nextcloud instance like a boss (or not). Furthermore, we will also deploy `step-ca` to manage our own Certificate Authority.


#
DISCLAIMER: This is should **not** be used in production. TLS/SSL Certificates are self-signed as this is done on a test environment. All passwords are crazy simple! The example describes how to deploy your own Certificate Authority. When deploying your services into the real world, you should use Let's encrypt.
#

The config described on this blog post was deployed on a Raspberry Pi 4 running Arch Linux for ARM.

## Intro

First, `Docker` and `docker-compose` are required, so go on and install them... I am waiting...

Now that docker is installed, I will quickly explain what we are going to do.   

- Traefik listens on port `:80` and `:443`, port `:80` is redirected to `:443`.
- Traefik sends requests to host `nextcloud.raspberry` to `nextcloud:80` and resquests to `portainer.raspberry` to `portainer:9000`.
- Nextcloud database `oc-db` and cache `oc-redis` are connected to an internal network that cannot be reached from the outside.
- Step-ca listens on `127.0.0.1:4343` so `step-cli` can reach the Certificate Authority, the container is also connected to the external network so Traefik can also talk to it in order to request certificates.

![diagram](/assets/pics/2021-05-03/diag.png "Deploy diagram")

### Docker networks
Please create two docker networks, containers will be attached to those networks.
```sh
docker network create -d bridge --attachable external
docker network create -d bridge --attachable internal
```

### /etc/hosts
Add `raspberry`, `portainer.raspberry` and `nextcloud.raspberry` to your `hosts` so you can access those services.
```sh
➜ cat /etc/hosts         
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback

IP_OF_SERVER raspberry portainer.raspberry nextcloud.raspberry
```

## Step-ca Certificate Authority
This section will quickly explain how to setup step-ca. `step-cli` is a command line client to communicate with step-ca service.   
[Official installation](https://smallstep.com/docs/step-cli/installation)

### Specific to Arch Linux Arm
   
`Step-ca` is not present in the repos and the `PKGBUILD` on AUR doesn't have `armv7h` support. Please use this PKGBUILD to install step-cli.   

    
```sh
# Maintainer: Max Furman <mx.furman@gmail.com>
# Maintainer: Sebastian Tiedtke <sebastiantiedtke@gmail.com>
# Maintainer: Nazar Mishturak <nazarmx@gmail.com>
_binname=step-cli
pkgname=$_binname-bin
pkgver=0.15.16
pkgrel=1
pkgdesc="A zero trust swiss army knife for working with X509, OAuth, JWT, OATH OTP, etc."
arch=('x86_64' 'aarch64' 'armv7h')
url="https://smallstep.com/cli"
license=('Apache')

source=("https://github.com/smallstep/cli/raw/v${pkgver}/autocomplete/bash_autocomplete"
    "https://github.com/smallstep/cli/raw/v${pkgver}/autocomplete/zsh_autocomplete")
source_aarch64=("https://github.com/smallstep/cli/releases/download/v${pkgver}/step_linux_${pkgver}_arm64.tar.gz")
source_x86_64=("https://github.com/smallstep/cli/releases/download/v${pkgver}/step_linux_${pkgver}_amd64.tar.gz")
source_armv7h=("https://github.com/smallstep/cli/releases/download/v${pkgver}/step_linux_${pkgver}_armv7.tar.gz")

sha256sums=('add3e078e394e265f6b6a3bf12af81cc7897410ae5e6a0d4ee7714a5b856a7be'
            '3e65c7f99484497e39d20eed3e4ceb4006e8db62dc9987f83a789bb575636e18')
sha256sums_aarch64=("3cfd09cfb763f283ce85e77e4b3cfc7cd4512a7f67a8dda42fa85d016f79d333")
sha256sums_x86_64=("5b2d244bc96cf33b8b69e5f46ec14d50691dca7cc559304a82d3da34c772fb0c")
sha256sums_armv7h=("8a3b1c6025658f47074aa2adbf79010c657e303863ea66a55bf9cf6da1a2ad55")

prepare() {
    sed -i "s/step/${_binname}/g" "zsh_autocomplete"
}

package() {
    install -Dm755 "step_$pkgver/bin/step" "$pkgdir/usr/bin/$_binname"
    install -Dm644 "step_$pkgver/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
    install -Dm644 "bash_autocomplete" "$pkgdir/usr/share/bash-completion/completions/$_binname"
    install -Dm644 "zsh_autocomplete" "$pkgdir/usr/share/zsh/site-functions/_${_binname}"
}
```

### Step-ca

Official documentation for installing and bootstrapping step-ca can be found on their official website.
[Docker installation](https://hub.docker.com/r/smallstep/step-ca)   
[Getting Started](https://smallstep.com/docs/step-ca/getting-started)

For a quick install follow those steps.
```sh
# init step ca and copy the FINGERPRINT
docker run --rm -it -v step_data:/home/step smallstep/step-ca step ca init

# Put the password previously chosen into /home/step/secrets/password
docker run --rm -it -v step_data:/home/step smallstep/step-ca vi /home/step/secrets/password

# Run step-ca docker container
docker run -d -p 127.0.0.1:4343:4343 --network external --name step-ca -v step_data:/home/step smallstep/step-ca

# Bootstrap
step ca bootstrap --ca-url https://localhost:4343 --fingerprint $FINGERPRINT

# add ACME provider
docker exec -it step-ca step ca provisioner add traefik --type ACME
```

### Add Traefik domain name to step-ca
You must add the domain name of your Traefik instance to step-ca configuration. 
```yaml
"dnsNames": [
                "localhost",
                "step-ca",
                "raspberry"
        ]
```

### Add CA to trust
Arch Linux
```sh
# Add the certificate to trust store
sudo trust anchor --store ./cert.crt
```

Ubuntu
```sh
sudo cp ./cert /usr/share/ca-certificates/
sudo update-ca-certificates
```

## Traefik
Traefik docker compose configuration.
```yaml
version: '3'

services:
  traefik:
    image: "traefik:latest"
    restart: always
    container_name: "traefik"
    command: 
      # Add docker provider to traefik.
      - "--providers.docker"
      # Setup two entry points, one for HTTP and the other to HTTPS. Entrypoints names are http and https.
      - "--entrypoints.http.address=:80"
      - "--entrypoints.https.address=:443"
      # Global HTTP -> HTTPS
      - "--entrypoints.http.http.redirections.entryPoint.to=https"
      - "--entrypoints.http.http.redirections.entryPoint.scheme=https"
      # Enable dashboard
      - "--api.dashboard=true"
      # Only expose specific containers.
      - --providers.docker.network=external
      - --providers.docker.constraints=Label(`tag`,`app-external`)
      - --providers.docker.exposedByDefault=false
      # Setup ACME for automatic certificates. For let's encrypt, just replace caServer with let's encrypt servers.
      - "--certificatesResolvers.stepca.acme.caServer=https://step-ca:4343/acme/traefik/directory"
      - "--certificatesResolvers.stepca.acme.email=user@raspberry.local"
      - "--certificatesResolvers.stepca.acme.storage=/etc/ssl/acme.json"
      - "--certificatesResolvers.stepca.acme.tlsChallenge=true"
      - "--providers.providersthrottleduration=100"
    labels:
      # Enable traefik for that container (traefik-ception)
      - "traefik.enable=true"
      - "tag=app-external"
      # Expose dashboard
      - "traefik.docker.network=external"
      - "traefik.http.routers.traefik.rule=Host(`traefik.raspberry`)"
      - "traefik.http.routers.traefik.entrypoints=https"
      - "traefik.http.routers.traefik.service=api@internal"
      - "traefik.http.routers.traefik.tls=true"
      # Set certificate resolver to our own ACME provider  
      - "traefik.http.routers.traefik.tls.certResolver=stepca"
    ports:
      # Expose ports to the outside world
      - "80:80"
      - "443:443"
    volumes:
      # So that Traefik can listen to the Docker events
      - /var/run/docker.sock:/var/run/docker.sock
      # Mount system ssl store inside the container. Because the system trusts our CA, traefik will also trust it. 
      - /etc/ssl/certs:/etc/ssl/certs
      - /etc/ssl/acme.json:/etc/ssl/acme.json
      - /etc/ca-certificates:/etc/ca-certificates
      # - ./traefik.toml:/traefik.toml
    networks:
      # Attach to external network 
      - external

networks:
  external:
    external:
      name: external
volumes:
  certs:
    driver: local
```

Then, bring the container up.
```sh
alarm🦄custodes [~/workspace/traefik] 
➜ docker-compose -f traefik.yaml up -d
```

## Nextcloud
```yaml
version: "3"

services:
# Postgres
  oc-db:
    restart: always
    image: postgres:11
    networks:
      - internal
    environment:
    - POSTGRES_USER=nextcloud
    - POSTGRES_PASSWORD=password
    - POSTGRES_DB=nextcloud
    volumes:
    - nextcloud-db:/var/lib/postgresql/data
# Redis
  oc-redis:
    image: redis:latest
    restart: always
    networks:
      - internal
    volumes:
      - nextcloud-redis:/data
# Nextcloud
  nextcloud:
    image: nextcloud:latest
    restart: always
    networks:
      - external
      - internal
    depends_on:
      - oc-redis
      - oc-db
    labels:
      # Activate traefik for tha container
      - "traefik.enable=true"
      - "tag=app-external"
      - "traefik.docker.network=external"
      # Middleware for nextcloud
      - "traefik.http.routers.nextcloud.middlewares=nextcloud,nextcloud_redirect"
      # Nextcloud host and activate tls
      - "traefik.http.routers.nextcloud.rule=Host(`nextcloud.raspberry`)"
      - "traefik.http.routers.nextcloud.tls=true"
      # Certificate resolver  
      - "traefik.http.routers.nextcloud.tls.certResolver=stepca"
      # HSTS
      - "traefik.http.middlewares.nextcloud.headers.stsSeconds=15552000"
      - "traefik.http.middlewares.nextcloud.headers.stsIncludeSubdomains=true"
      - "traefik.http.middlewares.nextcloud.headers.stsPreload=true"
      - "traefik.http.middlewares.nextcloud.headers.forceSTSHeader=true"
      - "traefik.http.middlewares.nextcloud.headers.contentSecurityPolicy=frame-ancestors 'self' raspberry *.raspberry"
      - "traefik.http.middlewares.nextcloud.headers.customFrameOptionsValue=SAMEORIGIN"
      # nextcloud_redirect
      - "traefik.http.middlewares.nextcloud_redirect.redirectregex.regex=/.well-known/(card|cal)dav"
      - "traefik.http.middlewares.nextcloud_redirect.redirectregex.replacement=/remote.php/dav/"
      # Service name and port
      - "traefik.http.routers.nextcloud.service=nextcloud"
      - "traefik.http.services.nextcloud.loadbalancer.server.port=80"
    environment:
      # Postgres
      - POSTGRES_DB=nextcloud
      - POSTGRES_USER=nextcloud
      - POSTGRES_PASSWORD=password
      - POSTGRES_HOST=oc-db
      - NEXTCLOUD_ADMIN_USER=admin
      - NEXTCLOUD_ADMIN_PASSWORD=adminpass
      # Trusted domain should be the same as your nextcloud domain
      - NEXTCLOUD_TRUSTED_DOMAINS=nextcloud.raspberry
      - TRUSTED_PROXIES=nextcloud.raspberry
      # Redis
      - REDIS_HOST=oc-redis
    volumes:
      - nextcloud-www:/var/www/html
      - nextcloud-apps:/var/www/html/custom_apps
      - nextcloud-config:/var/www/html/config
      - nextcloud-data:/var/www/html/data

networks:
  external:
    external:
      name: external
  internal:
    external:
      name: internal

volumes:
  nextcloud-www:
    driver: local
  nextcloud-apps:
    driver: local
  nextcloud-config:
    driver: local
  nextcloud-data:
    driver: local
  nextcloud-db:
    driver: local
  nextcloud-redis:
    driver: local
```

Bring the container up.
```sh
alarm🦄custodes [~/workspace/nextcloud] 
➜ docker-compose -f nextcloud.yaml up -d
```

## Portainer
```yaml
version: '3'

services:
  portainer:
    image: portainer/portainer-ce:latest
    container_name: "portainer"
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data
    labels:
      - "traefik.enable=true"
      - "tag=app-external"
      - "traefik.docker.network=external"
      - "traefik.http.routers.portainer.rule=Host(`portainer.raspberry`)"
      - "traefik.http.routers.portainer.entrypoints=https"
      - "traefik.http.routers.portainer.tls=true"
      - "traefik.http.routers.portainer.service=portainer"
      - "traefik.http.services.portainer.loadbalancer.server.port=9000"
      - "traefik.http.routers.portainer.tls.certResolver=stepca"
    networks:
      - external

networks:
  external:
    external:
      name: external

volumes:
  portainer_data:
    external: true
```

Bring the container up.
```sh
alarm🦄custodes [~/workspace/portainer] 
➜ docker-compose -f portainer.yaml up -d
```

## Adding a new service
It is very easy to add a new service to traefik. Just add those line to the docker compose file associated with your service. Traefik does not need to be restarted, it listens on the docker daemon to dynamically create routes and issue certificates.

Replace `SERVICE_NAME`, `HOSTNAME`, `SERVICE_PORT` with values specific to your service and complete the docker compose file.

```yaml
version: '3'

services:
  SERVICE_NAME:
    labels:
      - "traefik.enable=true"
      - "tag=app-external"
      - "traefik.docker.network=external"
      - "traefik.http.routers.SERVICE_NAME.rule=Host(`HOSTNAME`)"
      - "traefik.http.routers.SERVICE_NAME.entrypoints=https"
      - "traefik.http.routers.SERVICE_NAME.tls=true"
      - "traefik.http.routers.SERVICE_NAME.service=SERVICE_NAME"
      - "traefik.http.services.SERVICE_NAME.loadbalancer.server.port=SERVICE_PORT"
      - "traefik.http.routers.SERVICE_NAME.tls.certResolver=stepca"
    networks:
      - external

networks:
  external:
    external:
      name: external
```

## Why bother with internal and external network?
In this case, it is useless to have two networks, but if your server has multiple physical interfaces, you can publish ports to the internal interface. Alternatively, you can have a second traefik container (it can work with one instance but I think that two is better) that listens on the internal network and proxy requests to internal services.