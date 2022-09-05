# FROM golang:1.19 as build-env

# WORKDIR /

# COPY go.mod ./
# COPY go.sum ./
# RUN go mod download

# COPY main.go ./

# RUN go build -o /certificate-init-container

# FROM gcr.io/distroless/base:nonroot
# COPY --from=build-env /certificate-init-container /certificate-init-container

# CMD [ "certificate-init-container" ]

FROM scratch
COPY ./certificate-init-container ./certificate-init-container
ENTRYPOINT ["./certificate-init-container"]