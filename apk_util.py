#coding=utf-8
#created by SamLee 2020/6/3

# This file is part of Androguard.
#
# Copyright (C) 2012, Anthony Desnos <desnos at t0t0.fr>
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The main part of AndroidManifest.xml parsing was inspired by apk_parse
# For your interest, please refer to the original implementation => https://github.com/tdoly/apk_parse/blob/master/apk.py


import os
import sys
import struct
import zipfile
import traceback
import codecs

APK_MANIFEST = 'AndroidManifest.xml'

APICLOUD_MANIFEST_APPNAME = 'com.uzmap.pkg.uzapp.UZApplication'
APICLOUD_MANIFEST_APPVERSION = 'uz_version'

APK_MANIFEST_STARTTAG_BYTES = b'\x02\x01\x10\x00'
DEXHEAD_MAGICS = [b'\x64\x65\x78\x0A\x30\x33',\
                    b'\x64\x65\x79\x0A\x30\x33']

CHUNK_XML,CHUNK_STRING,CHUNK_TABLE,CHUNK_TABLEPACKAGE  = 0x0003,0x0001,0x0002,0x0200

def getFileSize(f):
    org_pos = f.tell()
    try:
        f.seek(0, os.SEEK_END)
        return f.tell()
    finally:
        f.seek(org_pos, os.SEEK_SET)


def isPossibleDexFile(dexFile,dexInfo=None):
    global DEXHEAD_MAGICS
    apkHead = dexFile.read(8)
    if len(apkHead)<8 or not (apkHead[0:6] in DEXHEAD_MAGICS and apkHead[-1:]==b'\x00'):
        return False
    dexFile.read(24)
    dexFileSize = struct.unpack('<i',dexFile.read(4))[0] #int.from_bytes(dexFile.read(4),'little')
    if dexInfo:
        actualFileSize = dexInfo.file_size
    else:
        actualFileSize = getFileSize(dexFile) if dexFile.seekable() else 8+24+4+len(dexFile.read())
    return dexFileSize == actualFileSize

def isPossibleManifest(manifest,manifestInfo=None):
    global CHUNK_XML,CHUNK_STRING
    manifestHeaders = manifest.read(16)
    if not manifestHeaders or len(manifestHeaders)<16:
        return False
    xmlHead = struct.unpack('<h',manifestHeaders[0:2])[0] #int.from_bytes(manifestHeaders[0:2],'little')
    xmlChunkSize = struct.unpack('<i',manifestHeaders[4:8])[0] #int.from_bytes(manifestHeaders[4:8],'little')
    strHead = struct.unpack('<h',manifestHeaders[8:10])[0] #int.from_bytes(manifestHeaders[8:10],'little')
    if manifestInfo:
        actualFileSize = manifestInfo.file_size
    else:
        actualFileSize = getFileSize(manifest) if manifest.seekable() else 16+len(manifest.read())
    return xmlHead==CHUNK_XML and strHead==CHUNK_STRING and xmlChunkSize==actualFileSize

def isPossibleArsc(arscFile,arscInfo=None):
    global CHUNK_TABLE,CHUNK_STRING, CHUNK_TABLEPACKAGE
    headInfo = arscFile.read(8)
    expectedChunkSize,actualChunkSize = struct.unpack('<i',headInfo[4:8])[0]  , 0  #int.from_bytes(headInfo[4:8],'little')
    if len(headInfo)<8 or struct.unpack('<h',headInfo[0:2])[0] != CHUNK_TABLE:  #int.from_bytes(headInfo[0:2],'little')
        return False
    actualChunkSize += 8 + len( arscFile.read(struct.unpack('<h',headInfo[2:4])[0] - 8) )  #int.from_bytes(headInfo[2:4],'little')
    headInfo = arscFile.read(8)
    if len(headInfo)<8 or struct.unpack('<h',headInfo[0:2])[0] != CHUNK_STRING:  #int.from_bytes(headInfo[0:2],'little')
        return False
    actualChunkSize += 8 + len( arscFile.read(struct.unpack('<i',headInfo[4:8])[0]  - 8) )  #int.from_bytes(headInfo[4:8],'little')
    headInfo = arscFile.read(8)
    if len(headInfo)<8 or struct.unpack('<h',headInfo[0:2])[0] != CHUNK_TABLEPACKAGE:  #int.from_bytes(headInfo[0:2],'little')
        return False
    if arscInfo:
        actualChunkSize = arscInfo.file_size
    else:
        actualChunkSize = getFileSize(arscFile) if arscFile.seekable() else actualChunkSize + 8 + len(arscFile.read())
    return expectedChunkSize == actualChunkSize

def isPossibleApkFile(filePath):
    if not zipfile.is_zipfile(filePath):
        return False
    try:
        manifestVerify,dexVerify, arscVerify = [], [], []
        with zipfile.ZipFile(filePath,'r') as apkArc:
            for zipInfo in apkArc.infolist():
                if zipInfo.filename=='AndroidManifest.xml':
                    with apkArc.open(zipInfo.filename,'r') as manifest:
                        manifestVerify.append( isPossibleManifest(manifest,zipInfo) )
                elif zipInfo.filename=='resources.arsc':
                    with apkArc.open(zipInfo.filename,'r') as arsc:
                        arscVerify.append( isPossibleArsc(arsc,zipInfo) )
                elif zipInfo.filename.startswith('classes') and zipInfo.filename.endswith('.dex'):
                    with apkArc.open(zipInfo.filename,'r') as apkDex:
                        dexVerify.append( isPossibleDexFile(apkDex,zipInfo) )
            # one AndroidManifest.xml, one resources.arsc and not less than one dex
            if len(manifestVerify)!=1:
                manifestVerify.append(False)
            if len(arscVerify)!=1:
                arscVerify.append(False)    
            if len(dexVerify)<1:
                dexVerify.append(False)

        return all(manifestVerify) and all(dexVerify) and all(arscVerify)
    except:
        print('error parsing file:'.format(filePath))
        traceback.print_exc()
        return False

UTF8_FLAG = 0x00000100

ATTR_TYPE_ATTRIBUTE = 2
ATTR_TYPE_DIMENSION = 5
ATTR_TYPE_FIRST_COLOR_INT = 28
ATTR_TYPE_FIRST_INT = 16
ATTR_TYPE_FLOAT = 4
ATTR_TYPE_FRACTION = 6
ATTR_TYPE_INT_BOOLEAN = 18
ATTR_TYPE_INT_COLOR_ARGB4 = 30
ATTR_TYPE_INT_COLOR_ARGB8 = 28
ATTR_TYPE_INT_COLOR_RGB4 = 31
ATTR_TYPE_INT_COLOR_RGB8 = 29
ATTR_TYPE_INT_DEC = 16
ATTR_TYPE_INT_HEX = 17
ATTR_TYPE_LAST_COLOR_INT = 31
ATTR_TYPE_LAST_INT = 31
ATTR_TYPE_NULL = 0
ATTR_TYPE_REFERENCE = 1
ATTR_TYPE_STRING = 3

COMPLEX_UNIT_MASK = 15
RADIX_MULTS = [0.00390625, 3.051758E-005, 1.192093E-007, 4.656613E-010]
DIMENSION_UNITS = ["px", "dip", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]

def complexToFloat(xcomplex):
    return (float)(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]

def getAttributeValue(vStr,vType,vData,stringList):
    
    if vType == ATTR_TYPE_STRING:
        return stringList[vStr]
    
    elif vType == ATTR_TYPE_ATTRIBUTE:
        return "?%s%08X" % ('android:' if (vData>>24)==1 else '', vData)

    elif vType == ATTR_TYPE_REFERENCE:
        return "@%s%08X" % ('android:' if (vData>>24)==1 else '', vData)

    elif vType == ATTR_TYPE_FLOAT:
        return struct.unpack("=f", struct.pack("=L", vData))[0]

    elif vType == ATTR_TYPE_INT_HEX:
        return "0x%08X" % vData

    elif vType == ATTR_TYPE_INT_BOOLEAN:
        if vData == 0:
            return False
        return True

    elif vType == ATTR_TYPE_DIMENSION:
        return "%f%s" % (complexToFloat(vData), DIMENSION_UNITS[vData & COMPLEX_UNIT_MASK])

    elif vType == ATTR_TYPE_FRACTION:
        return "%f%s" % (complexToFloat(vData) * 100, FRACTION_UNITS[vData & COMPLEX_UNIT_MASK])

    elif vType >= ATTR_TYPE_FIRST_COLOR_INT and vType <= ATTR_TYPE_LAST_COLOR_INT:
        return "#%08X" % vData

    elif vType >= ATTR_TYPE_FIRST_INT and vType <= ATTR_TYPE_LAST_INT:
        return (0x7fffffff & vData) - 0x80000000 if vData>0x7fffffff else vData

    return "<0x%X, type 0x%02X>" % (vData, vType)

def extractStringList(fileBytes,fOffset):
    '''
    fileHeader(8)
    header(2) + headerSize(2) + chunkSize(4) + stringCount(4) + styleOffsetCount(4) + flags(4) + stringsOffset(4) + stylesOffset(4)
        0:stringCount  stringOffset(4)
        0:styleOffsetCount  styleOffset(4)
    '''
    stringList = []
    chunkSize = struct.unpack('<I',fileBytes[fOffset+(1<<2):fOffset+(1<<2)+4])[0]
    flags = struct.unpack('<I',fileBytes[fOffset+(4<<2):fOffset+(4<<2)+4])[0]
    isUtf8 = (flags&UTF8_FLAG)!=0
    stringCount = struct.unpack('<I',fileBytes[fOffset+(2<<2):fOffset+(2<<2)+4])[0]
    stringsOffset = struct.unpack('<I',fileBytes[fOffset+(5<<2):fOffset+(5<<2)+4])[0] + fOffset
    stylesOffset = struct.unpack('<I',fileBytes[fOffset+(6<<2):fOffset+(6<<2)+4])[0]
    if stylesOffset!=0:
        stylesOffset += fOffset
    stringSize = chunkSize-stringsOffset if stylesOffset==0 else stylesOffset-stringsOffset
    #print(chunkSize,flags,stringCount,stringsOffset,stylesOffset,stringSize)
    rawStringDataBlock = fileBytes[stringsOffset : stringsOffset+stringSize]
    #print(rawStringDataBlock)
    STR_ZEND = b'\x00\x00'
    '''
    in python3 one byte is automatically converted to int while in python2 it is consider as str
    in order to make it work for both versions, just make it as a copy of length 1(without causing auto-conversion in python3)
    '''
    for i in range(stringCount):
        offset = struct.unpack('<I',fileBytes[fOffset+28+(i<<2):fOffset+28+(i<<2)+4])[0]
        if isUtf8:
            val = struct.unpack('=b',rawStringDataBlock[offset:offset+1])[0]
            more = (val & 0x80) != 0
            val &= 0x7f
            offset += 2 if more else 1
            val = struct.unpack('=b',rawStringDataBlock[offset:offset+1])[0]
            more = (val & 0x80) != 0
            val &= 0x7f
            length = (val << 8) | struct.unpack('=b',rawStringDataBlock[offset+1 : offset+2] )
            offset += 2 if more else 1
            stringList.append(rawStringDataBlock[offset:offset+length].decode('utf-8',errors='replace'))
        else:
            length = (struct.unpack('=b',rawStringDataBlock[offset+1:offset+2])[0] & 0xff) << 8 | struct.unpack('=b',rawStringDataBlock[offset:offset+1])[0] & 0xff
            length = (length<<1)
            offset += 2
            rawStringData = rawStringDataBlock[offset:offset+length]
            strEnd = rawStringData.find(STR_ZEND)
            if strEnd!=-1:
                rawStringData = rawStringData[:strEnd]
            stringList.append(rawStringData.decode('utf-16',errors='replace'))

    return stringList
'''
extract all attribute name-value pair from manifest file
return a list of name-value map ,  each item is correspondent to a specific tag in xml 
'''
def extractAttributes(fileBytes,onlySimpleAttr=True):
    global APK_MANIFEST_STARTTAG_BYTES,UTF8_FLAG,ATTR_TYPE_STRING
    #extract all string
    stringList = extractStringList(fileBytes,8)
    #print(stringList)
    '''
    startTag(4)+chunkSize(4)+lineNumber(4)+0xFFFFFFFF(4) + nameSpaceUri(4) + name(4) + flags(4) + attributeCount(4) + classAttribute(4)
        every attribute : NAMESPACE_URI(4) + NAME(4) + valueString(4) + valueType(4) + valueData(4)
        valueString,NAME are offset in the string block
    '''
    complexTypes = set([ATTR_TYPE_ATTRIBUTE,ATTR_TYPE_REFERENCE])
    tagAttrs = []
    tagIdx,attrCountIdx,attrStartIdx = -1,(7<<2),(9<<2)
    tagMrk = b'\xFF\xFF\xFF\xFF'
    while True:
        tagIdx = fileBytes.find(APK_MANIFEST_STARTTAG_BYTES,tagIdx+1)
        if tagIdx<0:
            break
        if fileBytes[tagIdx+12:tagIdx+12+4]!=tagMrk:
            continue
        tagName = stringList[struct.unpack('<I',fileBytes[tagIdx+20:tagIdx+24])[0]]
        attrCount = struct.unpack('<L',fileBytes[tagIdx+attrCountIdx:tagIdx+attrCountIdx+4])[0] & 0xFFFF
        attrs = {}
        for i in range(attrCount):
            attrBlock = fileBytes[tagIdx+attrStartIdx+((i*5)<<2):tagIdx+attrStartIdx+((i*5)<<2)+(5<<2)]
            attrType = (struct.unpack('<I',attrBlock[(3<<2):(3<<2)+4])[0]>>24)
            if onlySimpleAttr and attrType in complexTypes:
                continue
            nameIdx,valueIdx = struct.unpack('<I',attrBlock[(1<<2):(1<<2)+4])[0],struct.unpack('<I',attrBlock[(2<<2):(2<<2)+4])[0]
            valueData = struct.unpack('<I',attrBlock[(4<<2):(4<<2)+4])[0]
            attrs[stringList[nameIdx]] = getAttributeValue(valueIdx,attrType,valueData,stringList)
        if attrs:
            if tagName=='meta-data' and 'value' in attrs:
                attrs = {attrs['name']:attrs['value']}
            tagAttrs.append((tagName,attrs))

    return tagAttrs

def extractAPICloudInfo(filePath,isDefaultApk=False):
    global APK_MANIFEST,APICLOUD_MANIFEST_APPNAME,APICLOUD_MANIFEST_APPVERSION
    isApk = isPossibleApkFile(filePath) if not isDefaultApk else True
    if not isApk:
        return None
    try:
        uzAppInfo = None
        if not zipfile.is_zipfile(filePath):
            return uzAppInfo
        with zipfile.ZipFile(filePath,'r') as apkArc:
            with apkArc.open(APK_MANIFEST,'r') as manifest:
                mBytes = manifest.read()
                attrsList = extractAttributes(mBytes)
                manifest, applicationName, versionAttrs = {}, None, None
                for tagName,attrs in attrsList:
                    if tagName=='manifest':
                        manifest = attrs
                    elif tagName=='application' and 'name' in attrs:
                        applicationName = attrs['name']
                    elif tagName=='meta-data' and APICLOUD_MANIFEST_APPVERSION in attrs:
                        versionAttrs = attrs

                if applicationName==APICLOUD_MANIFEST_APPNAME and versionAttrs:
                    uzAppInfo = {}
                    uzAppInfo.update(manifest)
                    uzAppInfo.update(versionAttrs)

        return uzAppInfo
    except:
        print('error extracting apicloud info :{}'.format(filePath))
        traceback.print_exc()
        return None

def isPossibleAPICloudApk(filePath,isDefaultApk=False):
    if extractAPICloudInfo(filePath,isDefaultApk):
        return True
    return False


