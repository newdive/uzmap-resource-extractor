import os
import struct

class BytesReader:
    bigEndianFormatTypes = ['>b', '>B', '>h', '>H', '>i', '>I', '>q', '>Q', '>f', '>d']
    littleEndianFormatTypes = ['<b', '<B', '<h', '<H', '<i', '<I', '<q', '<Q', '<f', '<d']

    def __init__(self, dataBytes, littleEndian=True):
        self.data = dataBytes
        self.offset = 0
        self.littleEndian = littleEndian
        self.formatTypes = BytesReader.littleEndianFormatTypes if self.littleEndian else BytesReader.bigEndianFormatTypes

    def seek(self, off):
        self.offset = off

    def alignToFourBytes(self):
        self.offset = (self.offset+3)&0xFFFFFFFC

    def skip(self, length):
        self.offset += length

    def readBytes(self, length, seekOff=-1):
        self.offset = self.offset + length if seekOff == -1 else seekOff+length
        return self.data[self.offset-length: self.offset]

    def readByte(self, seekOff=-1):
        self.offset = self.offset + 1 if seekOff == -1 else seekOff+1
        return struct.unpack_from(self.formatTypes[0], self.data, self.offset-1)[0]

    def readUnsignedByte(self, seekOff=-1):
        self.offset = self.offset + 1 if seekOff == -1 else seekOff+1
        return struct.unpack_from(self.formatTypes[1], self.data,self.offset-1)[0]

    def readShort(self, seekOff=-1):
        self.offset = self.offset + 2 if seekOff == -1 else seekOff+2
        return struct.unpack_from(self.formatTypes[2], self.data, self.offset-2)[0]

    def readUnsignedShort(self, seekOff=-1):
        self.offset = self.offset + 2 if seekOff == -1 else seekOff+2
        return struct.unpack_from(self.formatTypes[3], self.data, self.offset-2)[0]

    def readInt(self, seekOff=-1):
        self.offset = self.offset + 4 if seekOff == -1 else seekOff+4
        return struct.unpack_from(self.formatTypes[4], self.data, self.offset-4)[0]

    def readUnsignedInt(self, seekOff=-1):
        self.offset = self.offset + 4 if seekOff == -1 else seekOff+4
        return struct.unpack_from(self.formatTypes[5], self.data, self.offset-4)[0]

    def readLong(self, seekOff=-1):
        self.offset = self.offset + 8 if seekOff == -1 else seekOff+8
        return struct.unpack_from(self.formatTypes[6], self.data, self.offset-8)[0]

    def readUnsignedLong(self, seekOff=-1):
        self.offset = self.offset + 8 if seekOff == -1 else seekOff+8
        return struct.unpack_from(self.formatTypes[7], self.data, self.offset-8)[0]

    def readFloat(self, seekOff=-1):
        self.offset = self.offset + 4 if seekOff == -1 else seekOff+4
        return struct.unpack_from(self.formatTypes[8], self.data, self.offset-4)[0]

    def readDouble(self, seekOff=-1):
        self.offset = self.offset + 8 if seekOff == -1 else seekOff+8
        return struct.unpack_from(self.formatTypes[9], self.data, self.offset-8)[0]

    def readShortArray(self, length, seekOff=-1):
        if length<1:
            return []
        result = []
        if seekOff>-1:
            self.seek(seekOff)
        for i in range(length):
            result.append(self.readShort())
        return result

    def readUnsignedLeb128(self):
        result, cur, count = 0, 0, 0
        while True:
            cur = self.readByte()
            result |= (cur & 0x7f) << (count * 7)
            count += 1
            if cur&0x80 != 0x80 or count >= 5:
                break
        if cur&0x80 == 0x80:
            raise Exception("invalid LEB128 sequence")
        return result
    
    def decodeUTF8Str(self):
        result = []
        while True:
            a = self.readByte()&0xFF
            if a == 0:
                return bytes(result).decode('utf-8')
            result.append(a)
            if a < 0x80:
                pass
            elif (a & 0xe0) == 0xc0:
                b = self.readByte()&0xFF
                if (b & 0xC0) != 0x80:
                    raise Exception("UTFDataFormatException: bad second byte")
                result.append(((a & 0x1F) << 6) | (b & 0x3F))
            elif (a & 0xf0) == 0xe0:
                b, c = self.readByte() & 0xff, self.readByte() & 0xff
                if ((b & 0xC0) != 0x80) or ((c & 0xC0) != 0x80):
                    raise Exception("UTFDataFormatException: bad second or third byte")
                result.append(((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F))
            else:
                raise Exception("UTFDataFormatException: bad byte")

    def readString(self):
        offset = self.readInt()
        curOffset = self.offset
        self.seek(offset)
        expectedLength = self.readUnsignedLeb128()
        try:
            resultStr = self.decodeUTF8Str()
            if len(resultStr) != expectedLength:
                raise Exception("Declared length {} doesn't match decoded length of {}".format(expectedLength,
                                                                                               len(resultStr)))
            return resultStr
        finally:
            self.seek(curOffset)



'''
reference com/android/dex/TableOfContents.java
'''
class TableOfContents:
    __slots__ = ('magic', 'checksum', 'signiture', 'fileSize', 'linkSize', 'linkOff', 'dataSize', 'dataOff',
                 'header', 'stringIds', 'typeIds', 'protoIds', 'fieldIds', 'methodIds', 'classDefs', 'mapList',
                 'typeLists', 'annotationSetRefLists', 'annotationSets', 'classDatas', 'codes', 'stringDatas', 'debugInfos', 'annotations',
                 'encodedArrays', 'annotationsDirectories')
    sectionTypeMap = {
        0x0000: 'header',
        0x0001: 'stringIds',
        0x0002: 'typeIds',
        0x0003: 'protoIds',
        0x0004: 'fieldIds',
        0x0005: 'methodIds',
        0x0006: 'classDefs',
        0x1000: 'mapList',
        0x1001: 'typeLists',
        0x1002: 'annotationSetRefLists',
        0x1003: 'annotationSets',
        0x2000: 'classDatas',
        0x2001: 'codes',
        0x2002: 'stringDatas',
        0x2003: 'debugInfos',
        0x2004: 'annotations',
        0x2005: 'encodedArrays',
        0x2006: 'annotationsDirectories',
    }

    def __init__(self, dataBytes):
        # initialize sections
        for k, v in TableOfContents.sectionTypeMap.items():
            setattr(self, v, (0, -1))
        bytesReader = BytesReader(dataBytes, littleEndian=True)
        self._readHeader(bytesReader)
        self._readMap(bytesReader)

    def _readHeader(self, dataBytes):
        self.magic = dataBytes.readBytes(8)
        self.checksum = dataBytes.readInt()
        self.signiture = dataBytes.readBytes(20)
        self.fileSize = dataBytes.readInt()
        headerSize = dataBytes.readInt()
        endianTag = dataBytes.readInt()
        self.linkSize = dataBytes.readInt()
        self.linkOff = dataBytes.readInt()
        self.mapList = (0, dataBytes.readInt())
        for k in ['stringIds','typeIds', 'protoIds', 'fieldIds', 'methodIds', 'classDefs']:
            setattr(self, k, (dataBytes.readInt(), dataBytes.readInt()))
        self.dataSize, self.dataOff = dataBytes.readInt(), dataBytes.readInt()

    # size, offset
    def _getSection(self, type):
        return getattr(self, TableOfContents.sectionTypeMap[type], None)

    def _updateSection(self, type, size, offset):
        setattr(self, TableOfContents.sectionTypeMap[type], (size, offset))

    def _readMap(self, dataBytes):
        dataBytes.seek(self.mapList[1])
        mapSize = dataBytes.readInt()
        previous = None
        for i in range(mapSize):
            type = dataBytes.readShort()
            dataBytes.skip(2)
            size, offset = dataBytes.readInt(), dataBytes.readInt()
            section = self._getSection(type)
            if section is None:
                continue
            if (section[0] != 0 and section[0] != size) or\
                    (section[1] != -1 and section[1] != offset):
                raise Exception("DexException: Unexpected map value for 0x{:04x}".format(type))
                #throw new DexException("Map is unsorted at " + previous + ", " + section)
            if section[0] == 0 or section[1] == -1:
                self._updateSection(type, size, offset)
                section = self._getSection(type)
            if previous is not None and previous[1] > section[1]:
                raise Exception("DexException: Map is unsorted at {}, {}".format(previous, section))
            previous = section


class SizeOf:
    UBYTE = 1
    USHORT = 2
    UINT = 4
    SIGNATURE = UBYTE * 20
    HEADER_ITEM = (8 * UBYTE) + UINT + SIGNATURE + (20 * UINT)
    STRING_ID_ITEM = UINT
    TYPE_ID_ITEM = UINT
    TYPE_ITEM = USHORT
    PROTO_ID_ITEM = UINT + UINT + UINT
    MEMBER_ID_ITEM = USHORT + USHORT + UINT
    CLASS_DEF_ITEM = 8 * UINT
    MAP_ITEM = USHORT + USHORT + UINT + UINT
    TRY_ITEM = UINT + USHORT + USHORT


class ValueType:
    ENCODED_BYTE = 0x00
    ENCODED_SHORT = 0x02
    ENCODED_CHAR = 0x03
    ENCODED_INT = 0x04
    ENCODED_LONG = 0x06
    ENCODED_FLOAT = 0x10
    ENCODED_DOUBLE = 0x11
    ENCODED_STRING = 0x17
    ENCODED_TYPE = 0x18
    ENCODED_FIELD = 0x19
    ENCODED_ENUM = 0x1b
    ENCODED_METHOD = 0x1a
    ENCODED_ARRAY = 0x1c
    ENCODED_ANNOTATION = 0x1d
    ENCODED_NULL = 0x1e
    ENCODED_BOOLEAN = 0x1f


class ClassDef:
    __slots__ = ('typeIndex', 'accessFlags', 'supertypeIndex', 'interfacesOffset',
                 'sourceFileIndex', 'annotationsOffset', 'classDataOffset', 'staticValuesOffset')

    def __init__(self,typeIndex, accessFlags,
            supertypeIndex, interfacesOffset, sourceFileIndex,
            annotationsOffset, classDataOffset, staticValuesOffset):
        self.typeIndex = typeIndex
        self.accessFlags = accessFlags
        self.supertypeIndex = supertypeIndex
        self.interfacesOffset = interfacesOffset
        self.sourceFileIndex = sourceFileIndex
        self.annotationsOffset = annotationsOffset
        self.classDataOffset = classDataOffset
        self.staticValuesOffset = staticValuesOffset


class FieldId:
    __slots__ = ('declaringClassIndex', 'typeIndex', 'nameIndex')

    def __init__(self,declaringClassIndex, typeIndex, nameIndex):
        self.declaringClassIndex = declaringClassIndex
        self.typeIndex = typeIndex
        self.nameIndex = nameIndex


class Field:
    __slots__ = ('fieldIndex', 'accessFlags')

    def __init__(self, fieldIndex, accessFlags):
        self.fieldIndex = fieldIndex
        self.accessFlags = accessFlags


class FieldInfo:
    def __init__(self):
        self.accessFlags = 0
        self.name, self.type = None, None



class Annotation:
    VISIBILITY_BUILD = 0
    VISIBILITY_RUNTIME = 1
    VISIBILITY_SYSTEM = 2

    def __init__(self, visibility, annoType, values):
        self.visibility = visibility
        self.atype = annoType
        self.values = values


class ClassValueParser:

    def __init__(self, dex, valueOffset):
        self.dex = dex
        self.valueOffset = valueOffset

    def processValues(self, stopIdx=-1):
        self.dex.data.seek(self.valueOffset)
        valueCount = self.dex.data.readUnsignedLeb128()
        fieldValues, readValueCount = [], stopIdx+1 if stopIdx>-1 else valueCount
        for i in range(readValueCount):
            fieldValues.append(self.parseValue())
        return fieldValues

    def parseValue(self):
        argAndType = self.dex.data.readByte() & 0xFF
        type = argAndType & 0x1F
        arg = (argAndType & 0xE0) >> 5
        size = arg + 1
        if type == ValueType.ENCODED_NULL:
            return type, None
        if type == ValueType.ENCODED_BOOLEAN:
            return type, arg == 1
        if type == ValueType.ENCODED_BYTE:
            return type, self.dex.data.readByte() & 0xFF
        if type == ValueType.ENCODED_CHAR:
            return type, self.parseNumber0(size, True)
        if type == ValueType.ENCODED_SHORT:
            return type, self.parseUnsignedInt(size)
        if type == ValueType.ENCODED_INT:
            return type, self.parseNumber0(size, True)
        if type == ValueType.ENCODED_LONG:
            return type, self.parseNumber0(size, True)
        if type == ValueType.ENCODED_FLOAT:
            return type, struct.unpack('>f', struct.pack('>I', self.parseNumber(size, False, 4)))[0]
        if type == ValueType.ENCODED_DOUBLE:
            return type, struct.unpack('>d', struct.pack('>Q', self.parseNumber(size, False, 8)))[0]
        if type == ValueType.ENCODED_STRING:
            strIdx = self.parseUnsignedInt(size)
            curOff = self.dex.data.offset
            strVal = self.dex.stringFromDescriptorIndex(strIdx)
            self.dex.data.seek(curOff)
            return type, strVal
        if type == ValueType.ENCODED_ARRAY:
            arrValCount = self.dex.data.readUnsignedLeb128()
            arrVals = []
            for i in range(arrValCount):
                arrVals.append(self.parseValue())
            return type, arrVals
        if type == ValueType.ENCODED_TYPE:
            typeIdx = self.parseUnsignedInt(size)
            curOff = self.dex.data.offset
            typeName = self.dex.stringFromTypeIndex(typeIdx)
            self.dex.data.seek(curOff)
            return type, typeName
        if type == ValueType.ENCODED_METHOD:
            # methodInfo
            return type, self.parseUnsignedInt(size)   # methodId index
        if type == ValueType.ENCODED_FIELD or type == ValueType.ENCODED_ENUM:
            # fieldInfo
            return type, self.parseUnsignedInt(size)   # fieldId index
        if type == ValueType.ENCODED_ANNOTATION:
            return type, self._readAnnotation()
        raise Exception("DecodeException: Unknown encoded value type: {:x}" .format(type))

    def _readAnnotation(self):
        typeIndex = self.dex.data.readUnsignedLeb128()
        size = self.dex.data.readUnsignedLeb128()
        valueMap = {}
        for i in range(size):
            nIdx = self.dex.data.readUnsignedLeb128()
            curOff = self.dex.data.offset
            name = self.dex.get_string(nIdx)
            self.dex.data.seek(curOff)
            valueMap[name] = self.parseValue()
        curOff = self.dex.data.offset
        annoType = self.dex.stringFromTypeIndex(typeIndex)
        self.dex.data.seek(curOff)
        return Annotation(None, annoType, valueMap)

    def parseUnsignedInt(self, byteCount):
        return self.parseNumber(byteCount, False, 0)

    def parseNumber0(self, byteCount, isSignExtended):
        return self.parseNumber(byteCount, isSignExtended, 0)

    def parseNumber(self, byteCount, isSignExtended, fillOnRight):
        result, last = 0, 0
        for i in range(byteCount):
            last = self.dex.data.readByte() & 0xFF
            result |= last << i * 8
        if fillOnRight != 0:
            for i in range(byteCount, fillOnRight):
                result <<= 8
        else:
            # abs(a) + abs(negative of a) = (1 << byteCount of a)
            if isSignExtended and (last & 0x80) != 0:
                result -= (1 << byteCount * 8)
        return result


class Dex:

    def __init__(self, dataBytes):
        self.data = BytesReader(dataBytes)
        self.tableOfContents = TableOfContents(dataBytes)
    
    def stringFromTypeIndex(self, idx):
        return self.stringFromDescriptorIndex(self.descriptorIndexFromTypeIndex(idx))

    def stringFromDescriptorIndex(self, idx):
        self._checkBounds(idx, self.tableOfContents.stringIds[0])
        stringOff = self.tableOfContents.stringIds[1] + (idx * SizeOf.STRING_ID_ITEM)
        self.data.seek(stringOff)
        return self.data.readString()

    def descriptorIndexFromTypeIndex(self, typeIndex):
       self._checkBounds(typeIndex, self.tableOfContents.typeIds[0])
       position = self.tableOfContents.typeIds[1] + (typeIndex * SizeOf.TYPE_ID_ITEM )
       return self.data.readInt(position)
    
    def readClassDef(self, classTypeName):
        offSet = self.tableOfContents.classDefs[1]
        for i in range(self.tableOfContents.classDefs[0]):
            self.data.seek(offSet)
            clsDef = self._readClassDef()
            if self.stringFromTypeIndex(clsDef.typeIndex)==classTypeName:
                return clsDef
            offSet += SizeOf.CLASS_DEF_ITEM
        return None
    
    def findFieldInfoFromClassDef(self, classDef, fieldName, isStatic=False):
        if not classDef or classDef.classDataOffset == 0:
            return -1, None
        offset = classDef.classDataOffset
        self.data.seek(offset)
        staticFieldsSize = self.data.readUnsignedLeb128()
        instanceFieldsSize = self.data.readUnsignedLeb128()
        directMethodsSize = self.data.readUnsignedLeb128()
        virtualMethodsSize = self.data.readUnsignedLeb128()
        staticFields = self._readFields(staticFieldsSize)
        instanceFields = self._readFields(instanceFieldsSize)
        # ignore methods
        targetFields = staticFields if isStatic else instanceFields
        for tfIdx, field in enumerate(targetFields):
            fieldId = self.getFieldIdByIndex(field.fieldIndex)
            fName = self.stringFromDescriptorIndex(fieldId.nameIndex)
            if fName == fieldName:
                fieldInfo = FieldInfo()
                fieldInfo.accessFlags = field.accessFlags
                fieldInfo.name = fName
                fieldInfo.type = self.stringFromTypeIndex(fieldId.typeIndex)
                return tfIdx, fieldInfo
        return -1, None
    
    def findFieldInfo(self, className, fieldName, isStatic=False):
        return self.findFieldInfoFromClassDef(self.readClassDef(className), fieldName, isStatic=isStatic)
    
    def getClassStaticFieldAndValue(self, className, fieldName):
        classDef = self.readClassDef(className)
        fIdx, fieldInfo = self.findFieldInfoFromClassDef(classDef, fieldName, isStatic=True)
        if not fieldInfo:
            return None, None
        if classDef.staticValuesOffset == 0: # static value is not defined
            return fieldInfo, None
        cvParser = ClassValueParser(self, classDef.staticValuesOffset)
        staticValues = cvParser.processValues(fIdx)
        return fieldInfo, staticValues[fIdx]

    def getFieldIdByIndex(self, fieldIndex):
        offSet = self.tableOfContents.fieldIds[1] + fieldIndex*SizeOf.MEMBER_ID_ITEM
        self.data.seek(offSet)
        return self._readFieldId()
    
    def _checkBounds(self, index, length):
        if index < 0 or index >= length:
            raise Exception('IndexOutOfBounds => index={}, length={}'.format(index, length))
    
    def _readFields(self, count):
        result = []
        fieldIndex = 0
        for i in range(count):
            fieldIndex += self.data.readUnsignedLeb128()
            accessFlags = self.data.readUnsignedLeb128()
            result.append(Field(fieldIndex, accessFlags))
        return result

    def _readFieldId(self):
        declaringClassIndex = self.data.readUnsignedShort()
        typeIndex = self.data.readUnsignedShort()
        nameIndex = self.data.readInt()
        return FieldId(declaringClassIndex, typeIndex, nameIndex)

    def _readClassDef(self):
        typeIndex = self.data.readInt()
        accessFlags = self.data.readInt()
        supertype = self.data.readInt()
        interfacesOffset = self.data.readInt()
        sourceFileIndex = self.data.readInt()
        annotationsOffset = self.data.readInt()
        classDataOffset = self.data.readInt()
        staticValuesOffset = self.data.readInt()
        return ClassDef(typeIndex, accessFlags, supertype,
                interfacesOffset, sourceFileIndex, annotationsOffset, classDataOffset,
                staticValuesOffset)
    

