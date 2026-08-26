FROM golang:1.21 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY attack_tests.sh /attack_tests.sh
COPY console-readme.md /console-readme.md
RUN CGO_ENABLED=0 go build -o /zerobox-server ./cmd/server
FROM gcr.io/distroless/static-debian12
COPY --from=build /zerobox-server /zerobox-server
COPY --from=build /attack_tests.sh /attack_tests.sh
COPY --from=build /console-readme.md /console-readme.md
ENTRYPOINT ["/zerobox-server"]
