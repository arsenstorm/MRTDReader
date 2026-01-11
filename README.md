# MRTDReader

> Forked from [AndyQ/NFCPassportReader](https://github.com/AndyQ/NFCPassportReader)

A Swift library for reading NFC-enabled ICAO 9303 compliant Machine Readable Travel Documents (MRTDs) using iOS 15+ CoreNFC APIs. Supports passports, national ID cards, residence permits, and other MRTD document types.

## Supported Features

* Basic Access Control (BAC)
* Secure Messaging
* Reads DG1 (MRZ data) and DG2 (Image) in both JPEG and JPEG2000 formats, DG7, DG11, DG12, DG14 and DG15 (also SOD and COM datagroups)
* Passive Authentication
* Active Authentication
* Chip Authentication (ECDH DES and AES keys tested, DH DES AES keys implemented and should work but currently not tested)
* PACE - currently only Generic Mapping (GM) supported
* Ability to dump document data and read it back in
* Uses Async/Await

## Supported Document Types

| Format | Size | Typical Documents |
|--------|------|------------------|
| **TD1** | ID-1 (credit card size) | National ID cards, residence permits |
| **TD2** | ID-2 (A7 size) | Some visas, travel documents |
| **TD3** | ID-3 (passport size) | Passports |

## Installation

### Swift Package Manager

MRTDReader may be installed via Swift Package Manager, by pointing to this repo's URL:

```
https://github.com/arsenstorm/MRTDReader
```

## Usage 

To use, you first need to create the MRZ Key which consists of the document number, date of birth and expiry date (including the checksums).
Dates are in YYMMDD format

For example:

```
<document number><document number checksum><date of birth><date of birth checksum><expiry date><expiry date checksum>

e.g. for Document nr 12345678, Date of birth 27-Jan-1998, Expiry 30-Aug-2025 the MRZ Key would be:

Document number - 12345678
Document number checksum - 8
Date Of birth - 980127
Date of birth checksum - 7
Expiry date - 250830
Expiry date checksum - 5

mrzKey = "12345678898012772508315"
```

Then on an instance of `MRTDReader`, call the `read` method passing in the configuration:

```swift
import MRTDReader

let reader = MRTDReader()

do {
    let config = MRTDReaderConfiguration(mrzKey: mrzKey)
    let document = try await reader.read(configuration: config)
    // document.passportMRZ, document.passportImage, document.firstName, etc.
} catch {
    // Handle MRTDReaderError
}
```

Supported data groups: COM, DG1, DG2, DG7, DG11, DG12, DG14 (partial), DG15, and SOD

### Legacy API

For backwards compatibility, the legacy API is still available:

```swift
let reader = MRTDReader()
let document = try await reader.readPassport(mrzKey: mrzKey)
```

### Custom Display Messages

You can customise the messages displayed in the NFC Session Reader by providing a `displayMessageHandler` callback:

```swift
let config = MRTDReaderConfiguration(
    mrzKey: mrzKey,
    displayMessageHandler: { displayMessage in
        switch displayMessage {
        case .requestPresentPassport:
            return "Hold your iPhone near an NFC enabled document."
        default:
            return nil
        }
    }
)
let document = try await reader.read(configuration: config)
```

### Active Authentication

A custom Active Authentication challenge can be provided to ensure that the challenge/response was specifically executed in the session and not replayed. The app can then send the `activeAuthenticationSignature` to a backend, along with the rest of the chip data to perform validation.

```swift
let config = MRTDReaderConfiguration(
    mrzKey: mrzKey,
    aaChallenge: customChallenge
)
```

## Logging

Logging is disabled by default for security reasons (cryptographic data could be logged). To enable verbose logging for debugging:

```swift
let config = MRTDReaderConfiguration(
    mrzKey: mrzKey,
    loggingEnabled: true  // WARNING: Sensitive data may be logged
)
```

Or enable globally:

```swift
MRTDLogging.isEnabled = true
```

## Passive Authentication

Passive Authentication is part of the library and can be used to ensure that an MRTD is valid and hasn't been tampered with.

It requires a set of CSCA certificates in PEM format from a master list (either from a country that publishes their master list, or the ICAO PKD repository). See the scripts folder for details on how to get and create this file.

```swift
let config = MRTDReaderConfiguration(
    mrzKey: mrzKey,
    masterListURL: masterListURL
)
```

## Troubleshooting

* If when doing the initial Mutual Authenticate challenge, you get an error with SW1 code 0x63, SW2 code 0x00, reason: No information given, then this is usually because your MRZ key is incorrect, and possibly because your document number is not quite right. If your document number in the MRZ contains a '<' then you need to include this in the MRZKey - the checksum should work out correct too. For more details, check out App-D2 in the ICAO 9303 Part 11 document (https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)

  e.g. if the bottom line on the MRZ looks like:
  `12345678<8AUT7005233M2507237<<<<<<<<<<<<<<06`
  
  In this case the document number is 12345678 but is padded out with an additional <. This needs to be included in the MRZ key used for BAC.
  e.g. `12345678<870052332507237` would be the key used.

## Migration from NFCPassportReader

If you're migrating from the old `NFCPassportReader` package, the following type aliases are provided for backwards compatibility:

| Old Name | New Name |
|----------|----------|
| `NFCPassportReader` (import) | `MRTDReader` |
| `PassportReader` | `MRTDReader` |
| `PassportReadingConfiguration` | `MRTDReaderConfiguration` |
| `PassportReaderTrackingDelegate` | `MRTDReaderTrackingDelegate` |
| `NFCPassportModel` | `MRTDModel` |
| `NFCPassportReaderError` | `MRTDReaderError` |
| `NFCPassportLogging` | `MRTDLogging` |

## Thanks

[Andy Qua](https://github.com/AndyQ) for the original implementation of this library ([NFCPassportReader](https://github.com/AndyQ/NFCPassportReader)).
