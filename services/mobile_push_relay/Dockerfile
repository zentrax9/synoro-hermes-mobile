ARG PYTHON_IMAGE=python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7
FROM ${PYTHON_IMAGE}
WORKDIR /app
COPY services/mobile_push_relay /app/mobile_push_relay
COPY services/mobile_push_relay/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt
RUN mkdir -p /tmp && chown 65532:65532 /tmp
USER 65532:65532
ENV PORT=8080 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# The relay authenticates its own bearer credential and does not need client-supplied
# forwarded headers.  Keep Uvicorn's proxy-header trust disabled so an upstream cannot
# forge scheme or client metadata.
CMD ["uvicorn", "mobile_push_relay.app:app_from_environment", "--factory", "--host", "0.0.0.0", "--port", "8080"]
