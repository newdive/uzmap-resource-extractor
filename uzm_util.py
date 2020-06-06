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
import entropy
from concurrent.futures import ThreadPoolExecutor
import threading
from queue import Queue
import time
import multiprocessing
import importlib

'''
文件使用rc4算法进行加密 rc4的key数据定义在rodata中
0:20*4 byte 数据映射的取值

208:208+33 apk的签名串 用于校验
208+33: 208+33+9*4 为key数据 分4段存储 需要合并处理
2020/4/26 
jni注册使用的类名字符串常量 "com/uzmap/pkg/uzcore/external/Enslecb"
这个字符串常量之前的 9byte 1段的4段数据 还有33 byte的apk签名串
之前固定位置的方式对有些不适用

得到key数据在利用 [0:20]byte的索引数组取出20byte的key值
2020/6/5
从原先的tools.py 迁移到 uzm_util.py
'''
JNI_PACKAGE_BYTES = 'com/uzmap/pkg/uzcore/external/Enslecb'.encode('utf-8')

# pycryptodome rc4 implementation
CRYPTODOME_ARC4 = None
try:
    CRYPTODOME_ARC4 = importlib.import_module('Crypto.Cipher.ARC4')
except:pass

def extractRC4Key(soFile):
    global JNI_PACKAGE_BYTES
    keyStr,keyIdx = None,None
    if isinstance(soFile,str):
        soFile = open(soFile,'rb') if os.path.exists(soFile) else None

    with soFile as f:
        elffile = ELFFile(f)
        littleEndian = elffile.little_endian
        dataSection,dataContent = elffile.get_section_by_name('.rodata'),None
        if dataSection:
            dataContent = dataSection.data()
        if dataContent and dataContent.find(JNI_PACKAGE_BYTES)>=80+9*4:
            pkgIdx = dataContent.find(JNI_PACKAGE_BYTES)
            #little endian bytes
            keyIdx = [struct.unpack('<I' if littleEndian else '>I',dataContent[i:i+4])[0] for i in range(0,20*4,4)]
            keyStr = dataContent[pkgIdx-9*4:pkgIdx].replace(b'\x00',b'').decode('utf-8')
    #print(keyIdx)
    #print(keyStr)
    return ''.join([keyStr[idx] for idx in keyIdx]) if keyStr else None

'''
#sample data for rc4 key data source (not the rc4 key itself)
preKeyIdx = [0x13,0x6,0x1f,0xa,0x8,0x12,0x3,0x16,0xb,0x0,0x12,0xc,0x19,0x6,0x12,0x9,0xe,0x2,0x17,0x1a]
rawKeyData = '988f520873542ac4a8df3cbfa8937024'
'''

def getPreKey(rawKey,keyIdxArr):
    return ''.join([rawKey[idx] for idx in keyIdxArr])

def computeRC4KeyMap(rc4Key):
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

def decrypt(dataBytes,rc4Key):
    global CRYPTODOME_ARC4
    if CRYPTODOME_ARC4:
        rc4 = CRYPTODOME_ARC4.new(rc4Key.encode('utf-8') if isinstance(rc4Key,type(' ')) else rc4Key)
        return rc4.decrypt(dataBytes)
    isBytes,isByteArray = isinstance(dataBytes,bytes),isinstance(dataBytes,bytearray)
    decDataBytes = []
    keyMap = computeRC4KeyMap(rc4Key)
    R3,R4 = 0, 0
    for i in range(len(dataBytes)):
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
        org = dataBytes[i]
        decDataBytes.append(org^keyMap[R5])
    
    return bytes(bytearray(decDataBytes)) if isBytes else bytearray(decDataBytes) if isByteArray else decDataBytes

'''
只有 js html css config.xml key.xml 进行了加密 其他文件没有 不需要解密
'''
enc_exts = ['js','html','css']
def needDecryptFile(fileName):
    global enc_exts
    extIdx = fileName.rfind('.')
    ext = fileName[extIdx+1:] if extIdx>-1 else None
    return  ext in enc_exts or 'config.xml' in fileName or 'key.xml' in fileName

def decryptSingleFile(targetFile,rc4Key,saveTo=None):
    if not os.path.exists(targetFile):
        return None
    if not needDecryptFile(targetFile):
        return None
    decContent = None
    with open(targetFile,'rb') as f:
        decContent = decrypt(f.read(),rc4Key)
    
    if saveTo:
        with open(saveTo,'wb') as f:
            f.write(decContent)
    return decContent

def decryptResourceFiles(folder):
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
            decryptResult = decryptSingleFile(tFile,saveTo)
            if not decryptResult:
                continue
            print('decrypt:{} => {}'.format(tFile,saveTo))

#python3.7.0 zipfile '_SharedFile'.seek calls 'writing' method instead of '_writing' 
def isBuggyZipfile():
    return sys.version_info.major==3 and sys.version_info.minor==7 and sys.version_info.micro<1

def extractRC4KeyFromApk(apkFilePath):
    if not os.path.exists(apkFilePath):
        print('{} does not exists'.format(apkFilePath))
        return None
    with zipfile.ZipFile(apkFilePath) as apkFile:
        apkResList = apkFile.namelist()
        soFiles = []
        for fname in apkResList:
            if fname.startswith('lib/') and fname.endswith('libsec.so'):
                with apkFile.open(fname) as soContent:
                    elfHeader = soContent.read(6)
                    #check elffile format(https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
                    if elfHeader[1]==ord('E') and elfHeader[2]==ord('L') and elfHeader[3]==ord('F'):
                        soFiles.append(fname)
        if not soFiles:
            print('libsec.so file not exists in apk file')
            return None
        for soFile in soFiles:
            with apkFile.open(soFile,'r') as soContent:
                soTmp = None
                if not soContent.seekable() or isBuggyZipfile():
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

def isResourceEncrypted(apkFilePath):
    '''
    可以通过判断 apk 中的类 compile.Properties.smode 的值 ： true表示有加密 false表示未加密
    但目前没办法直接通过解析 apk的字节码来判断对应类方法的返回值，所以先简单的从 assets/widget/config.xml 文件进行判断
    app第一个需要解密的文件是config.xml，如果这个文件没有加密 则说明其它文件也一样没有加密  反之亦然
    '''
    if not os.path.exists(apkFilePath):
        print('{} does not exists'.format(apkFilePath))
        return False
    confFile = 'assets/widget/config.xml'
    rawXmlFileHead = '<?xml'.encode('utf-8')
    with zipfile.ZipFile(apkFilePath) as apkFile:
        confFileBytes = None
        try:
            confFileBytes = apkFile.open(confFile).read()
        except:
            pass
        if not confFileBytes:
            print('{} does not exists in apk'.format(confFile))
            return False
        return confFileBytes.find(rawXmlFileHead) == -1

'''
判断熵的大小 一般加密的文件熵都超过0.9
(媒体文件除外，媒体文件的熵一般都在0.8-1之间)
'''
def isVeryLikelyEncrypted(dataBytes):
    entropyValue = entropy.shannonEntropy(dataBytes) if len(dataBytes)<=512 else entropy.gzipEntropy(dataBytes)
    return entropyValue>=0.9

def decryptAllResourcesInApk(apkFilePath,saveTo=None,printLog=False):
    resEncrypted = isResourceEncrypted(apkFilePath)
    rc4Key = None
    if resEncrypted:
        rc4Key = extractRC4KeyFromApk(apkFilePath)
        if not rc4Key:
            if printLog:
                print('fail to extract rc4 key')
            return None
    allAssets = iterateAllNeedDecryptAssets(apkFilePath)
    decryptMap = {}
    if allAssets:
        storeFolder = os.path.dirname(os.path.abspath(apkFilePath))
        saveTo = saveTo.strip()
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
            rawContent = fileContent.read()
            decContent = decrypt(rawContent,rc4Key=rc4Key) if resEncrypted and isVeryLikelyEncrypted(rawContent)  else rawContent #
            fileContent.close()
            resDecrypted = '{}/{}'.format(storeFolder,fName)
            decryptMap[fName] = resDecrypted 
            if not os.path.exists(os.path.dirname(resDecrypted)):
                os.makedirs(os.path.dirname(resDecrypted))
            with open(resDecrypted,'wb') as f:
                f.write(decContent)
            if printLog:
                sys.stdout.write('decrypt {}\r'.format(fName))
                sys.stdout.flush()
        if printLog:
            print()

    return decryptMap

def _decryptHandle(fName,rawContent,rc4Key,resEncrypted,msgQueue):
    decContent = decrypt(rawContent,rc4Key) if resEncrypted and isVeryLikelyEncrypted(rawContent) else rawContent 
    msgQueue.put_nowait((fName,decContent))

def decryptAllResourcesInApkParallel(apkFilePath,saveTo=None,printLog=False,procPool=None,msgQueue=None):
    resEncrypted,rc4Key = isResourceEncrypted(apkFilePath),None
    if resEncrypted:
        rc4Key = extractRC4KeyFromApk(apkFilePath)
        if not rc4Key:
            if printLog:
                print('fail to extract rc4 key')
            return None
    #print('decryptAllResourcesInApkParallel',apkFilePath,resEncrypted,rc4Key)
    allAssets = iterateAllNeedDecryptAssets(apkFilePath)
    decryptMap = {}
    if allAssets:
        storeFolder = os.path.dirname(os.path.abspath(apkFilePath))
        saveTo = saveTo.strip()
        if saveTo :
            if not os.path.exists(saveTo):
                os.makedirs(saveTo)
            storeFolder = saveTo

        if storeFolder.endswith('/') or storeFolder.endswith('\\'):
            storeFolder = storeFolder[0:-1]
        if not procPool:
            procPool = multiprocessing.Pool(processes=max(2, multiprocessing.cpu_count() ) ) 
        if not msgQueue:
            msgQueue = multiprocessing.Manager().Queue(0)
        def subHandle(allAssets,rc4Key,resEncrypted,procPool,msgQueue,globalStates):
            while True:
                assetFile = next(allAssets,None)
                if not assetFile:
                    break
                fName,fileContent = assetFile
                rawContent = fileContent.read()
                fileContent.close()
                procPool.apply_async(_decryptHandle,args=(fName,rawContent,rc4Key,resEncrypted,msgQueue))
                #executor.submit(decryptHandle,fName,rawContent,rc4Key,resEncrypted,msgQueue)
                globalStates['submittedFiles'] += 1
            globalStates['submitCompleted'] = True

        globalStates = {'submittedFiles':0,'processedFiles':0,'submitCompleted':False}
        subTh = threading.Thread(target=subHandle,args=(allAssets,rc4Key,resEncrypted,procPool,msgQueue,globalStates))
        subTh.start()

        while True:
            if globalStates['submitCompleted'] and globalStates['processedFiles']>=globalStates['submittedFiles']:
                break
            if msgQueue.empty():
                time.sleep(0.01)
                continue
            fName,decContent = msgQueue.get_nowait()
            globalStates['processedFiles'] += 1
            msgQueue.task_done()
            resDecrypted = '{}/{}'.format(storeFolder,fName)
            decryptMap[fName] = resDecrypted 
            if not os.path.exists(os.path.dirname(resDecrypted)):
                os.makedirs(os.path.dirname(resDecrypted))
            with open(resDecrypted,'wb') as f:
                f.write(decContent)
            if printLog:
                #sys.stdout.write('\r{}'.format(' '*96))
                #sys.stdout.flush()
                sys.stdout.write('{}/{}  decrypt {}\r'.format(globalStates['processedFiles'],globalStates['submittedFiles'],fName))
                sys.stdout.flush()
        if printLog:
            print('completed')

    return decryptMap
