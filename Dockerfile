FROM alpine:latest

RUN apk add --no-cache gcc make pkgconfig pcsc-lite-dev openssl-dev rust cargo

ADD config /tmp/config
ADD emvpt /tmp/emvpt
ADD terminalsimulator /tmp/terminalsimulator
RUN cd /tmp/emvpt && cargo test
RUN cd /tmp/terminalsimulator && cargo test
WORKDIR /tmp/terminalsimulator

ENTRYPOINT [ "cargo", "run", "--" ]