#FROM gcr.io/distroless/base:nonroot
FROM alpine
WORKDIR /
COPY ./certificate-init-container ./certificate-init-container
ENTRYPOINT ["./certificate-init-container"]