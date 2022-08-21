FROM golang:1.18 as build-env

WORKDIR /go/src/github.com/thoughtworks-dpds/certificate-init-container
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .
RUN go build -o ./bin/certificate-init-container .

FROM gcr.io/distroless/base:nonroot
COPY --from=build-env /go/src/github.com/thoughtworks-dpds/certificate-init-container/bin/certificate-init-container /bin/

ENTRYPOINT ["/bin/certificate-init-container"]

# though the code runes locally have tried several other dockerfile configs, 
# including the method used in Hightowers' example; though so far all fail to run the image

