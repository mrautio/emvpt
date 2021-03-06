![Build and test](https://github.com/mrautio/emvpt/workflows/Docker%20Image%20CI/badge.svg)

# emvpt - Minimum Viable Payment Terminal

Project's intention is to support simple EMV transaction cases for chip and contactless/NFC.

## Terminal simulator run

Note!
- You'll need a smart card reader device.
- If you need a test payment card, you can check [emv-card-simulator](https://github.com/mrautio/emv-card-simulator) project out.

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

* [EMV Contact Specifications](https://www.emvco.com/emv-technologies/contact/)
* [EMV Contactless Specifications](https://www.emvco.com/emv-technologies/contactless/)
  * EMV Contactless Book C-2 - Kernel 2 (MasterCard)
  * EMV Contactless Book C-3 - Kernel 3 (Visa)
* ISO codes
  * [Processing codes](http://www.fintrnmsgtool.com/iso-processing-code.html)
  * [Country codes](https://www.currency-iso.org/dam/downloads/lists/list_one.xml)
    * [FI country code](https://www.iso.org/obp/ui/#iso:code:3166:FI)
