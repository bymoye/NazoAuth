FROM docker.io/library/python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY .github/e2e-requirements.txt /tmp/e2e-requirements.txt

RUN pip install --no-cache-dir --require-hashes \
    -r /tmp/e2e-requirements.txt
