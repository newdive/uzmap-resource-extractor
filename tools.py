#coding=utf-8
#created by SamLee 2020/3/6

import os
import sys
import math
from elftools.elf.elffile import ELFFile
import zipfile
import tempfile
import shutil
import struct

'''
文件使用rc4算法进行加密 rc4的key数据定义在rodata中
0:20*4 byte 数据的取值
208:208+33 apk的签名串 用于校验
208+33: 208+33+9*4 为key数据 分4段存储 需要合并处理
得到key数据在利用 [0:20]byte的索引数组取出20byte的key值
'''
def extractRC4Key(soFile):
    keyStr,keyIdx = None,None
    if isinstance(soFile,str):
        soFile = open(soFile,'rb') if os.path.exists(soFile) else None

    with soFile as f:
        elffile = ELFFile(f)
        dataSection,dataContent = elffile.get_section_by_name('.rodata'),None
        if dataSection:
            dataContent = dataSection.data()
        if dataContent and len(dataContent)>208+33+36:
            #little endian bytes
            keyIdx = [struct.unpack('<I',dataContent[i:i+4])[0] for i in range(0,20*4,4)]
            keyStr = dataContent[208+33:208+33+36].replace(b'\x00',b'').decode('utf-8')
    return ''.join([keyStr[idx] for idx in keyIdx]) if keyStr else None

#sample data for rc4 key data source (not the rc4 key itself)
preKeyIdx = [0x13,0x6,0x1f,0xa,0x8,0x12,0x3,0x16,0xb,0x0,0x12,0xc,0x19,0x6,0x12,0x9,0xe,0x2,0x17,0x1a]
rawKeyData = '988f520873542ac4a8df3cbfa8937024'

def getPreKey(rawKey=None,keyIdxArr=None):
    global rawKeyData,preKeyIdx
    if rawKey is None:
        rawKey,keyIdxArr = rawKeyData,preKeyIdx
    return ''.join([rawKey[idx] for idx in keyIdxArr])

def computeRC4KeyMap(rc4Key=None):
    preKey = rc4Key
    if rc4Key is None or isinstance(rc4Key,tuple):
        preKey = getPreKey(rc4Key[0] if rc4Key else None,rc4Key[1] if rc4Key else None)
    blockA = [ord(a) for a in ( preKey*(math.ceil(256/len(preKey))) )[0:256]]
    blockB = [i for i in range(256)]
    reg2 = 0
    for i in range(256):
        reg3 = blockB[i]
        reg2 += blockA[i] + blockB[i]
        reg6 = (((reg2>>0x1F) >> 0x18) + reg2) & 0xFFFFFF00
        reg2 -= reg6
        blockB[i] = blockB[reg2]
        blockB[reg2] = reg3
    return blockB

def decrypt(dataBytes,statisticsOut=None,rc4Key=None):
    decDataBytes = [b for b in dataBytes]
    keyMap = computeRC4KeyMap(rc4Key)
    R3,R4 = 0, 0
    for i in range(len(decDataBytes)):
        R3 += 1
        R5 = ((R3>>0x1f)>>0x18)
        R6 = (R3 + R5 )& 0xFFFFFF00
        R3 -= R6
        R6 = keyMap[R3]
        R4 = R4 + R6
        R5 = (((R4>>0x1f)>>0x18) + R4) & 0xFFFFFF00
        R4 = R4 - R5
        keyMap[R3] = keyMap[R4]
        keyMap[R4] = R6
        R5 = (keyMap[R3] + R6) & 0xFF
        org = decDataBytes[i]
        decDataBytes[i] ^= keyMap[R5]
        if statisticsOut is not None:
            if not org in statisticsOut:
                statisticsOut[org] = set()
            statisticsOut[org].add(decDataBytes[i])
    
    return bytes(bytearray(decDataBytes)) if isinstance(dataBytes,bytes) else bytearray(decDataBytes) if isinstance(dataBytes,bytearray) else decDataBytes

'''
只有 js html css config.xml key.xml 进行了加密 其他文件没有 不许要解密
'''
enc_exts = ['js','html','css']
def needDecryptFile(fileName):
    global enc_exts
    extIdx = fileName.rfind('.')
    ext = fileName[extIdx+1:] if extIdx>-1 else None
    return  ext in enc_exts or 'config.xml' in fileName or 'key.xml' in fileName

def decryptSingleFile(targetFile,saveTo=None,statisticsOut=None):
    if not os.path.exists(targetFile):
        return None
    if not needDecryptFile(targetFile):
        return None
    decContent = None
    with open(targetFile,'rb') as f:
        statsO = None
        if statisticsOut is not None:
            statsO = statisticsOut[targetFile] = {}
        decContent = decrypt(f.read(),statsO)
    
    if saveTo:
        with open(saveTo,'wb') as f:
            f.write(decContent)
    return decContent

def decryptResourceFiles(folder,statisticsOut=None):
    if not os.path.exists(folder):
        return
    
    targetFiles = []
    if os.path.isdir(folder):
        for root, dirs, files in os.walk(folder):
            targetFiles.extend(['{}/{}'.format(root,f) for f in files])
    else:
        targetFiles.append(folder)
    
    if targetFiles:
        for tFile in targetFiles:
            extIdx = tFile.rfind('.')
            saveTo = '{}_decrypted.{}'.format(tFile[0:extIdx],tFile[extIdx+1:]) if extIdx>-1 else '{}_decrypted'.format(tFile)
            if os.path.exists(saveTo):
                continue
            decryptResult = decryptSingleFile(tFile,saveTo,statisticsOut)
            if not decryptResult:
                continue
            print('decrypt:{} => {}'.format(tFile,saveTo))

def extractRC4KeyFromApk(apkFilePath):
    if not os.path.exists(apkFilePath):
        print('{} does not exists'.format(apkFilePath))
        return None
    with zipfile.ZipFile(apkFilePath) as apkFile:
        apkResList = apkFile.namelist()
        soFile = None
        for fname in apkResList:
            if fname.startswith('lib/') and fname.endswith('libsec.so'):
                soFile = fname
                break
        if not soFile:
            print('libsec.so file not exists in apk file')
            return None
        with apkFile.open(soFile,'r') as soContent:
            soTmp = None
            if not soContent.seekable():
                soTmp = tempfile.mkstemp('.tmp','tmp',os.path.dirname(os.path.abspath(apkFilePath)))
                with open(soTmp[1],'wb') as soTmpC:
                    shutil.copyfileobj(soContent,soTmpC)
                soContent.close()
                soContent = open(soTmp[1],'rb')
            rc4Key = extractRC4Key(soContent)
            if soTmp:
                os.close(soTmp[0])
                os.remove(soTmp[1])
            return rc4Key
    return None

def iterateAllNeedDecryptAssets(apkFilePath):
    if not os.path.exists(apkFilePath):
        print('{} does not exists'.format(apkFilePath))
        return
    with zipfile.ZipFile(apkFilePath) as apkFile:
        apkResList = apkFile.namelist()
        for resName in apkResList:
            if resName.startswith('assets/widget/'):
                if needDecryptFile(resName):
                    yield resName,apkFile.open(resName)

def decryptAllResourcesInApk(apkFilePath,saveTo=None,printLog=False):
    rc4Key = extractRC4KeyFromApk(apkFilePath)
    if not rc4Key:
        if printLog:
            print('fail to extract rc4 key')
        return None
    allAssets = iterateAllNeedDecryptAssets(apkFilePath)
    decryptMap = {}
    if allAssets:
        storeFolder = os.path.dirname(os.path.abspath(apkFilePath))
        if saveTo :
            if not os.path.exists(saveTo):
                os.makedirs(saveTo)
            storeFolder = saveTo
        if storeFolder.endswith('/') or storeFolder.endswith('\\'):
            storeFolder = storeFolder[0:-1]

        while True:
            assetFile = next(allAssets,None)
            if not assetFile:
                break
            fName,fileContent = assetFile
            decContent = decrypt(fileContent.read(),rc4Key=rc4Key)
            fileContent.close()
            resDecrypted = '{}/{}'.format(storeFolder,fName)
            decryptMap[fName] = resDecrypted 
            if not os.path.exists(os.path.dirname(resDecrypted)):
                os.makedirs(os.path.dirname(resDecrypted))
            with open(resDecrypted,'wb') as f:
                f.write(decContent)
            if printLog:
                print('decrypt {} => {}'.format(fName,resDecrypted))

    return decryptMap
        
