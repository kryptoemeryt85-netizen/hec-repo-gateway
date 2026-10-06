FROM python:3.13-alpine3.22
ARG BUILD_VERSION
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache git && python -m pip install --no-cache-dir pytest==9.1.1
WORKDIR /app
COPY gateway.py safe_source.py regression.py /app/
ENV PYTHONDONTWRITEBYTECODE=1 GOODWE_WRITE=0
CMD ["python", "-u", "/app/gateway.py"]
