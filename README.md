# tproxy-vercel

A TypeScript implementation of the Telegram WEB proxy for Vercel.

This project is based on [telegramdesktop/tproxy-server](https://github.com/telegramdesktop/tproxy-server). The reason i did this is that a proper MTProxy requires a server and an open port, and deploying on Vercel makes it possible to set all of this up for free.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/wdkqxd/tproxy-vercel&env=TPROXY_HOST,TPROXY_SECRET,TPROXY_TOKEN_KEY)

## Quick start

```bash
pnpm install
cp .env.example .env

openssl rand -hex 32   # TPROXY_TOKEN_KEY
openssl rand -hex 16   # TPROXY_SECRET

# deploy with dlx
pnpm dlx vercel link
pnpm dlx vercel env add TPROXY_HOST production
pnpm dlx vercel env add TPROXY_SECRET production
pnpm dlx vercel env add TPROXY_TOKEN_KEY production
pnpm dlx vercel --prod
```

Connect in Telegram client:

```
Proxy server: your-domain.vercel.app
Proxy secret: PROXY_SECRET value
```

## Variables

`TPROXY_HOST` (required): domain the proxy is served on. It must match the production alias.

`TPROXY_SECRET` (required): MTProxy secret

`TPROXY_TOKEN_KEY` (required): 32 bytes used to sign tokens

`TPROXY_BASE_PATH` (optional): a prefix if the proxy is not served at the domain root

`TPROXY_LONG_POLL_MS` (optional): idle timeout, 25000 by default

## Development

```bash
pnpm dev          # vercel dev
pnpm typecheck
pnpm check        # biome
```
