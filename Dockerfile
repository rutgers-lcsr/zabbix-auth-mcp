FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

# Runs as root so it can read the letsencrypt privkey.pem (mode 640).
#
# PORT defaults to 8443. With SSL_CERTFILE/SSL_KEYFILE set, uvicorn terminates
# TLS itself; leave them unset when a reverse proxy in front terminates TLS.
# With HTTP_PORT set, a second listener redirects ACME challenges to services
# and everything else to https (see http_redirect.py).
CMD ["sh", "-c", "if [ -n \"$HTTP_PORT\" ]; then uvicorn http_redirect:app --host 0.0.0.0 --port $HTTP_PORT --lifespan off & fi; exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8443} ${SSL_CERTFILE:+--ssl-certfile $SSL_CERTFILE --ssl-keyfile $SSL_KEYFILE}"]
