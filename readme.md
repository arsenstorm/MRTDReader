# NFCPassportReader

> Forked from [AndyQ/NFCPassportReader](https://github.com/AndyQ/NFCPassportReader)

This package handles reading an NFC Enabled passport using iOS 15 CoreNFC APIs.

Supported features:
* Basic Access Control (BAC)
* Secure Messaging
* Reads DG1 (MRZ data) and DG2 (Image) in both JPEG and JPEG2000 formats, DG7, DG11, DG12, DG14 and DG15 (also SOD and COM datagroups)
* Passive Authentication
* Active Authentication
* Chip Authentication (ECDH DES and AES keys tested, DH DES AES keys implemented and should work but currently not tested)
* PACE - currently only Generic Mapping (GM) supported
* Ability to dump passport stream and read it back in
* Uses Async/Await

## Installation

### Swift Package Manager

NFCPassportReader may be installed via Swift Package Manager, by pointing to this repo's URL:

```
https://github.com/arsenstorm/NFCPassportReader
```

## Usage 
To use, you first need to create the Passport MRZ Key which consists of the passport number, date of birth and expiry date (including the checksums).
Dates are in YYMMDD format

For example:

```
<passport number><passport number checksum><date of birth><date of birth checksum><expiry date><expiry date checksum>

e.g. for Passport nr 12345678, Date of birth 27-Jan-1998, Expiry 30-Aug-2025 the MRZ Key would be:

Passport number - 12345678
Passport number checksum - 8
Date Of birth - 980127
Date of birth checksum - 7
Expiry date - 250830
Expiry date checksum - 5

mrzKey = "12345678898012772508315"
```

Then on an instance of `PassportReader`, call the `readPassport` method passing in the mrzKey:

```swift
let passportReader = PassportReader()

do {
    let passport = try await passportReader.readPassport(mrzKey: mrzKey)
    // passport.passportMRZ, passport.passportImage, etc.
} catch {
    // Handle NFCPassportReaderError
}
```

Supported data groups: COM, DG1, DG2, DG7, DG11, DG12, DG14 (partial), DG15, and SOD

You can customise the messages displayed in the NFC Session Reader by providing a `customDisplayMessage` callback:

```swift
let passport = try await passportReader.readPassport(
    mrzKey: mrzKey,
    customDisplayMessage: { displayMessage in
        switch displayMessage {
        case .requestPresentPassport:
            return "Hold your iPhone near an NFC enabled passport."
        default:
            return nil
        }
    }
)
```

Extended mode reads (not supported by all passports) can be enabled by passing in the useExtendedMode flag to the readPassport function.
This will increase the number of bytes that can be read in a call and may be required for some passports that use long AA keys (some Australian passports for example).

A custom Active Authentication challenge can be provided to the `PassportReader` to ensure that the challenge/response was specifically executed in the session and not replayed. The app can then send the `activeAuthenticationSignature` to a backend, along with the rest of the chip data to perform validation.


## Logging

Additional logging (very verbose) can be enabled on the `PassportReader` by passing in a log level on creation:

```swift
let reader = PassportReader(logLevel: .debug)
``` 

## Other info

### PassiveAuthentication
Passive Authentication is now part of the main library and can be used to ensure that an E-Passport is valid and hasn't been tampered with.

It requires a set of CSCA certificates in PEM format from a master list (either from a country that publishes their master list, or the ICAO PKD repository). See the scripts folder for details on how to get and create this file.

## Troubleshooting

* If when doing the initial Mutual Authenticate challenge, you get an error with and SW1 code 0x63, SW2 code 0x00, reason: No information given, then this is usualy because your MRZ key is incorrect, and possibly because your passport number is not quite right.  If your passport number in the MRZ contains a '<' then you need to include this in the MRZKey - the checksum should work out correct too.  For more details, check out App-D2 in the ICAO 9303 Part 11 document (https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)
<br><br>e.g. if the bottom line on the MRZ looks like:
12345678<8AUT7005233M2507237<<<<<<<<<<<<<<06
<br><br>
In this case the passport number is 12345678 but is padded out with an additonal <. This needs to be included in the MRZ key used for BAC.
e.g. 12345678<870052332507237 would be the key used.

## Thanks

[Andy Qua](https://github.com/AndyQ) for the original implementation of this library.
