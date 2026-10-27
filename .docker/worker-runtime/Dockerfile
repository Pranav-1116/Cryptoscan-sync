# Dedicated controlled dispatcher only, NEVER the untrusted parser image.
# Supply reviewed image@sha256 references for BOTH build arguments. The release
# packager subsequently requires the resulting worker image's registry digest.
ARG DOCKER_CLI_IMAGE
ARG WORKER_IMAGE
FROM ${DOCKER_CLI_IMAGE} AS cli
FROM ${WORKER_IMAGE}
USER root
COPY --from=cli /usr/local/bin/docker /usr/local/bin/docker
USER cryptoscan
