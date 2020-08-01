FROM rust:latest

RUN apt-get update && apt-get install -y libpcsclite-dev

ADD config /tmp/config
ADD emvpt /tmp/emvpt
ADD terminalsimulator /tmp/terminalsimulator
RUN cd /tmp/emvpt && cargo test
RUN cd /tmp/terminalsimulator && cargo test
WORKDIR /tmp/terminalsimulator

ENTRYPOINT [ "cargo", "run", "--" ]