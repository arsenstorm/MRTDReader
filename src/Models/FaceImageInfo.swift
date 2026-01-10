//
//  FaceImageInfo.swift
//

import Foundation

/// Facial image data as specified in ISO/IEC 19794-5
public struct FaceImageInfo: Equatable {
    public let expression: Expression?
    public let eyeColor: EyeColor?
    public let faceImageType: FaceImageType?
    public let features: Features?
    public let hairColor: HairColor?
    public let imageColorSpace: ImageColorSpace?
    public let imageDataType: ImageDataType?
    public let sourceType: SourceType?
    
    @available(iOS 13, macOS 10.15, *)
    static func from(dg2: DataGroup2) -> FaceImageInfo {
        FaceImageInfo(
            expression: Expression(rawValue: dg2.expression),
            eyeColor: EyeColor(rawValue: dg2.eyeColor),
            faceImageType: FaceImageType(rawValue: dg2.faceImageType),
            features: Features(rawValue: dg2.featureMask),
            hairColor: HairColor(rawValue: dg2.hairColor),
            imageColorSpace: ImageColorSpace(rawValue: dg2.imageColorSpace),
            imageDataType: ImageDataType(rawValue: dg2.imageDataType),
            sourceType: SourceType(rawValue: dg2.sourceType)
        )
    }
    
    /// Expression code (ISO 19794-5 Section 5.5.7)
    public enum Expression: Int {
        case unspecified = 0x0000
        case neutral = 0x0001
        case smileClosed = 0x0002
        case smileOpen = 0x0003
        case raisedEyebrows = 0x0004
        case eyesLookingAway = 0x0005
        case squinting = 0x0006
        case frowning = 0x0007
    }

    /// Eye color code (ISO 19794-5 Section 5.5.4)
    public enum EyeColor: Int {
        case unspecified = 0x00
        case black = 0x01
        case blue = 0x02
        case brown = 0x03
        case gray = 0x04
        case green = 0x05
        case multiColored = 0x06
        case pink = 0x07
        case unknown = 0xFF
    }
    
    /// Face image type (ISO 19794-5 Section 5.7.1)
    public enum FaceImageType: Int {
        case basic = 0x00
        case fullFrontal = 0x01
        case tokenFrontal = 0x02
    }
    
    /// Feature flags (ISO 19794-5 Section 5.5.6)
    public enum Features: Int {
        case featuresAreSpecified = 0x000001
        case glasses = 0x000002
        case moustache = 0x000004
        case beard = 0x000008
        case teethVisible = 0x000010
        case blink = 0x000020
        case mouthOpen = 0x000040
        case leftEyePatch = 0x000080
        case rightEyePath = 0x000100
        case darkGlasses = 0x000200
        case distortingMedicalCondition = 0x000400
    }
    
    /// Hair color code (ISO 19794-5 Section 5.5.5)
    public enum HairColor: Int {
        case unspecified = 0x00
        case bald = 0x01
        case black = 0x02
        case blonde = 0x03
        case brown = 0x04
        case gray = 0x05
        case white = 0x06
        case red = 0x07
        case green = 0x08
        case blue = 0x09
        case unknown = 0xFF
    }
    
    /// Color space code (ISO 19794-5 Section 5.7.4)
    public enum ImageColorSpace: Int {
        case unspecified = 0x00
        case rgb24 = 0x01
        case yuv422 = 0x02
        case gray8 = 0x03
        case other = 0x04
    }
    
    /// Image data type (ISO 19794-5 Section 5.7.2)
    public enum ImageDataType: Int {
        case jpeg = 0x00
        case jpeg2000 = 0x01
    }
    
    /// Source type (ISO 19794-5 Section 5.7.6)
    public enum SourceType: Int {
        case unspecified = 0x00
        case staticPhotoUnknownSource = 0x01
        case staticPhotoDigitalCam = 0x02
        case staticPhotoScanner = 0x03
        case videoFrameUnknownSource = 0x04
        case videoFrameAnalogCam = 0x05
        case videoFrameDigitalCam = 0x06
        case unknown = 0x07
    }
}
