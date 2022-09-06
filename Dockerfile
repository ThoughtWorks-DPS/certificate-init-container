FROM gcr.io/distroless/base:nonroot
WORKDIR /
COPY ./certificate-init-container ./certificate-init-container
ENTRYPOINT ["./certificate-init-container"]