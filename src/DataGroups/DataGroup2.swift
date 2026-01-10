//
//  DataGroup2.swift
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
public class DataGroup2: DataGroup {
    
    // MARK: - Public Properties
    
    public private(set) var nrImages: Int = 0
    public private(set) var versionNumber: Int = 0
    public private(set) var lengthOfRecord: Int = 0
    public private(set) var numberOfFacialImages: Int = 0
    public private(set) var facialRecordDataLength: Int = 0
    public private(set) var nrFeaturePoints: Int = 0
    public private(set) var gender: Int = 0
    public private(set) var eyeColor: Int = 0
    public private(set) var hairColor: Int = 0
    public private(set) var featureMask: Int = 0
    public private(set) var expression: Int = 0
    public private(set) var poseAngle: Int = 0
    public private(set) var poseAngleUncertainty: Int = 0
    public private(set) var faceImageType: Int = 0
    public private(set) var imageDataType: Int = 0
    public private(set) var imageWidth: Int = 0
    public private(set) var imageHeight: Int = 0
    public private(set) var imageColorSpace: Int = 0
    public private(set) var sourceType: Int = 0
    public private(set) var deviceType: Int = 0
    public private(set) var quality: Int = 0
    public private(set) var imageData: [UInt8] = []

    public override var datagroupType: DataGroupId { .DG2 }

    // MARK: - Image Headers (ISO 19794-5)
    
    private static let facHeader: [UInt8] = [0x46, 0x41, 0x43, 0x00]  // "FAC\0"
    private static let jpegHeader: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]
    private static let jpeg2000Header: [UInt8] = [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A]
    private static let jpeg2000Codestream: [UInt8] = [0xFF, 0x4F, 0xFF, 0x51]
    
    // MARK: - Init
    
    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }

    #if !os(macOS)
    public func getImage() -> UIImage? {
        guard !imageData.isEmpty else { return nil }
        return UIImage(data: Data(imageData))
    }
    #endif

    // MARK: - Parsing
    
    override func parse(_ data: [UInt8]) throws {
        // Biometric Information Template (0x7F61)
        try verifyTag(try getNextTag(), equals: 0x7F61)
        _ = try getNextLength()
        
        // Number of instances (0x02)
        try verifyTag(try getNextTag(), equals: 0x02)
        nrImages = Int(try getNextValue()[0])
        
        // Biometric Information Group Template (0x7F60)
        try verifyTag(try getNextTag(), equals: 0x7F60)
        _ = try getNextLength()
        
        // Biometric Header Template (0xA1) - skip
        try verifyTag(try getNextTag(), equals: 0xA1)
        _ = try getNextValue()
        
        // Biometric Data (0x5F2E or 0x7F2E)
        try verifyTag(try getNextTag(), oneOf: [0x5F2E, 0x7F2E])
        try parseISO19794_5(data: try getNextValue())
    }
    
    private func parseISO19794_5(data: [UInt8]) throws {
        // Validate FAC header
        guard data.prefix(4).elementsEqual(Self.facHeader) else {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: 0x46,
                actualTag: Int(data[0])
            )
        }
        
        var offset = 4
        
        // General record header
        versionNumber = readInt(data, &offset, 4)
        lengthOfRecord = readInt(data, &offset, 4)
        numberOfFacialImages = readInt(data, &offset, 2)
        
        // Facial record data
        facialRecordDataLength = readInt(data, &offset, 4)
        nrFeaturePoints = readInt(data, &offset, 2)
        gender = readInt(data, &offset, 1)
        eyeColor = readInt(data, &offset, 1)
        hairColor = readInt(data, &offset, 1)
        featureMask = readInt(data, &offset, 3)
        expression = readInt(data, &offset, 2)
        poseAngle = readInt(data, &offset, 3)
        poseAngleUncertainty = readInt(data, &offset, 3)
        
        // Skip feature points (8 bytes each)
        offset += nrFeaturePoints * 8
        
        // Image information
        faceImageType = readInt(data, &offset, 1)
        imageDataType = readInt(data, &offset, 1)
        imageWidth = readInt(data, &offset, 2)
        imageHeight = readInt(data, &offset, 2)
        imageColorSpace = readInt(data, &offset, 1)
        sourceType = readInt(data, &offset, 1)
        deviceType = readInt(data, &offset, 2)
        quality = readInt(data, &offset, 2)
        
        // Validate image format
        guard data.count >= offset + Self.jpeg2000Codestream.count else {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        
        let isValidFormat = data[offset...].starts(with: Self.jpegHeader) ||
                           data[offset...].starts(with: Self.jpeg2000Header) ||
                           data[offset...].starts(with: Self.jpeg2000Codestream)
        
        guard isValidFormat else {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        
        imageData = Array(data[offset...])
    }
    
    // MARK: - Helpers
    
    private func readInt(_ data: [UInt8], _ offset: inout Int, _ length: Int) -> Int {
        let result = binToInt(data[offset..<(offset + length)])
        offset += length
        return result
    }
}
