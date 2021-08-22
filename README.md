# traefik-auth-cloudflare

Forward auth server to verify Cloudflare Access JWT tokens with traefik

## Description

`traefik-auth-cloudflare` is designed to be a forward auth server for [traefik](https://github.com/containous/traefik) and [Cloudflare Access](https://www.cloudflare.com/products/cloudflare-access/).

When forwarding a user's request to your application, Cloudflare Access will include a signed JWT as a HTTP header. This JWT needs to be authenticated to ensure the request has been signed by Cloudflare and has gone through their servers.

Documentation on how to validate the JWT can be found here https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/.

Using `traefik-auth-cloudflare`, you can configure your `traefik` instance to correctly authenticate cloudflare requests, and you can serve multiple authenticated applications from a single instance.

## Example

Look into the [example](example/) directory to find example `docker-compose.yml` and `traefik.toml` files.

## How to use

- Start an instance of `traefik-auth-cloudflare` in the same docker network as `traefik`. ideally this is a distinct network from your applications.

```bash
# create network for traefik->traefik-auth-cloudflare communication

$ docker network create traefik-auth

# start traefik-auth-cloudflare
# you need to set the auth domain you configured on cloudflare and pass the audiences as env vars

$ docker run -d --network traefik-auth --name traefik-auth-cloudflare --env MYDOMAIN_COM=audience akohlbecker/traefik-auth-cloudflare --auth-domain https://foo.cloudflareaccess.com

# add traefik to your `traefik-auth` docker network (left to the reader)

$ docker network connect traefik-auth TRAEFIK_CONTAINER
```

- Configure your frontend to authenticate requests using `traefik-auth-cloudflare`

```bash
# start your app with auth settings

$ docker run \
  --label "traefik.frontend.auth.forward.address=http://traefik-auth-cloudflare/" \
  ....
```

- Optionally, configure traefik to forward the authenticated user header to your application

```bash
# start your app with auth user forward
# the http header is `X-Auth-Email`

$ docker run \
  --label "traefik.frontend.auth.forward.authResponseHeaders=X-Auth-Email" \
  ....
```
