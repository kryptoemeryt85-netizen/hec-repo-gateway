FROM python:3.13-alpine3.22
ARG BUILD_VERSION
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache git yq \
    && python -m pip install --no-cache-dir \
       pytest==9.1.1 \
       highspy==1.15.1 \
       numpy==2.5.3 \
       Jinja2==3.1.6 \
       MarkupSafe==3.0.4 \
       iniconfig==2.3.0 \
       packaging==26.3 \
       pluggy==1.6.0 \
       Pygments==2.21.0
WORKDIR /app
COPY gateway.py safe_source.py regression.py /app/
ENV PYTHONDONTWRITEBYTECODE=1 GOODWE_WRITE=0
CMD ["python", "-u", "/app/gateway.py"]
