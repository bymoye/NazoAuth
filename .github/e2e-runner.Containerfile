FROM python:3.13-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY .github/e2e-requirements.txt /tmp/e2e-requirements.txt

RUN pip install --no-cache-dir --require-hashes \
    -r /tmp/e2e-requirements.txt
