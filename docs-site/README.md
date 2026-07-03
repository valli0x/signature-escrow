# mpcoven docs (Docusaurus)

Documentation site served at **https://mpcoven.net/docs/** (`baseUrl: /docs/`).

## Build & deploy
```bash
npm install
npm run build            # -> build/  (static, Node 18 recommended)
# deploy: copy build/ to the server at /root/mpcoven/build/docs/
```
nginx serves it via a `location /docs/ { root /usr/share/nginx/html; try_files $uri $uri/ /docs/404.html; }`
block in `/root/mpcoven/nginx-ssl.conf`.

> Build note: pin `webpack` to `5.97.1` (see package.json `overrides`) — newer
> webpack + Docusaurus 3.7 fails ProgressPlugin schema validation.
