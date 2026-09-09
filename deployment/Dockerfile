ARG SCANNER_PLATFORM=linux/amd64
FROM --platform=${SCANNER_PLATFORM} sonarsource/sonar-scanner-cli:11@sha256:46341f2c2dc560381414e90347885f5cddc716db080adcbafc1cac13e1473094 AS scanner

FROM python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f

LABEL org.opencontainers.image.title="Scankeep" \
      org.opencontainers.image.description="Web service for operating SonarQube scans" \
      org.opencontainers.image.licenses="Apache-2.0"

ARG SECURITY_REFRESH=manual
RUN echo "Security refresh: ${SECURITY_REFRESH}" \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends git openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --requirement /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && python -m pip uninstall --yes pip setuptools wheel

WORKDIR /opt/scankeep
RUN groupadd --gid 1000 scankeep \
    && useradd --uid 1000 --gid 1000 --no-create-home scankeep
COPY --from=scanner --chown=1000:1000 /opt/sonar-scanner /opt/sonar-scanner
COPY --chown=1000:1000 scankeep/*.py ./scankeep/
COPY --chown=1000:1000 scankeep/static ./scankeep/static
COPY --chown=1000:1000 scankeep/templates ./scankeep/templates
COPY LICENSE /usr/share/licenses/scankeep/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/scankeep/THIRD_PARTY_NOTICES.md

ENV PATH=/opt/sonar-scanner/bin:${PATH} \
    PYTHONPATH=/opt/scankeep \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCANKEEP_DATA_DIR=/var/lib/scankeep \
    SONAR_USER_HOME=/var/lib/scankeep/cache \
    TMPDIR=/var/lib/scankeep/work

USER 1000:1000
EXPOSE 5002

ENTRYPOINT ["python", "-m", "gunicorn"]
CMD ["--bind=0.0.0.0:5002", "--workers=1", "--threads=4", "--timeout=60", "--graceful-timeout=30", "--access-logfile=-", "--error-logfile=-", "scankeep.app:app"]
