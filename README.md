![Build and test](https://github.com/mrautio/emvpt/workflows/Docker%20Image%20CI/badge.svg)

# emvpt

Minimum Viable Payment Terminal

## Terminal simulator run

Note! You'll need a smart card reader device to run the simulator.

```sh
terminalsimulator$ cargo run -- --help
```

## Library

```sh
emvpt$ cargo test
```

## Docker

```sh
docker build -t emvpt -f Dockerfile . && docker run --rm -t emvpt
```

## Update dependencies

```sh
emvpt$ cargo upgrade && cargo update && cargo audit
terminalsimulator$ cargo upgrade && cargo update && cargo audit
```

## References

* http://www.fintrnmsgtool.com/iso-processing-code.html
* https://www.currency-iso.org/dam/downloads/lists/list_one.xml
* https://www.iso.org/obp/ui/#iso:code:3166:FI
