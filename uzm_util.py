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
import threading
import time
import multiprocessing
import importlib
import file_util

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

2020/6/6 将tools.py迁移至此
'''
JNI_PACKAGE_BYTES = 'com/uzmap/pkg/uzcore/external/Enslecb'.encode('utf-8')
CRYPTODOME_ARC4 = None
try:
    CRYPTODOME_ARC4 = importlib.import_module('Crypto.Cipher.ARC4')
except:pass

# rc4 initial state for uz_version < 1.2.0
mrc4_initial_states = [239, 157, 102, 150, 29, 86, 207, 230, 165, 46, 102, 181, 75, 90, 17, 62, 153, 44, 78, 204]

hexBytesSet = set([ord(a) for a in '0123456789abcdefABCDEF'])
def isHexStrBytes(targetBytes):
    global hexBytesSet
    for a in targetBytes:
        if ord(a) not in hexBytesSet:
            return False
    return True

'''
hex区块由连续4个长度为9的字节构成
每块字节都是 8个 0-f 的字符 加上一个 0x00 字节结尾
'''
def findLegalHexStrBlock(byteSource,endIdx):
    startIdx = endIdx - 9*4
    while startIdx>=0:
        foundMatch,unMatchSkip = True, 1
        for i in range(4):
            byteBlock = byteSource[startIdx+i*9: startIdx+i*9+9]
            if ord(byteBlock[-1])!=0 or not isHexStrBytes(byteBlock[0:8]):
                foundMatch = False
                if i>0:
                    unMatchSkip = (4-i)*9
                break
        if foundMatch:
            return startIdx, startIdx+9*4
        startIdx = startIdx - unMatchSkip
    return -1,-1

# keyIdx的长度为0x14*4  每个idx对应的值的范围是 [0,0x20)
#旧版本中有的keyIdx的位置略有变化  可以通过遍历尝试的方法来检测
def findBestMatchKeyIdx(dataContent, keyStr, keyStartIdx, rawEncryptedContent, keyLen=0x14, littleEndian=True):
    if not rawEncryptedContent:
        return None
    dFmt = '<I' if littleEndian else '>I'
    tKeyIdx,dIdx = [], 0
    rawEntropyValue = entropy.calculateEntropy(rawEncryptedContent)
    while dIdx<keyStartIdx:
        if len(tKeyIdx)>0:
            tKeyIdx.pop(0)
        while dIdx<keyStartIdx and len(tKeyIdx)<keyLen:
            idxVal = struct.unpack(dFmt,dataContent[dIdx:dIdx+4])[0]
            if idxVal>0x20 or idxVal<0:
                tKeyIdx.clear()
                dIdx += 4
                break
            tKeyIdx.append(idxVal)
            dIdx += 4
        if len(tKeyIdx)==keyLen:
            encKey = ''.join([keyStr[idx] for idx in tKeyIdx]) 
            decBytes = decrypt(rawEncryptedContent, encKey)
            entropyValue = entropy.calculateEntropy(decBytes)
            #print(tKeyIdx,len(decBytes), rawEntropyValue, '=>', entropyValue )
            if entropyValue<0.7:
                return tKeyIdx
    return None

digitLetters = set([ord(a) for a in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'])
def extractAsciiStrings(dataContent):
    global digitLetters
    lStrings,strStart = [], 0
    for i in range(len(dataContent)):
        a = ord(dataContent[i])
        if a == 0:
            if strStart<i:
                lStrings.append(dataContent[strStart : i].decode('utf-8'))
            strStart = i+1
        elif a not in digitLetters:
            strStart = i+1

    return lStrings

# part of rc4 key for version before 1.2.0
def findEnslecbocKey(dataContent):
    lStrings = extractAsciiStrings(dataContent)
    str10Counts = {}
    for lStr in lStrings:
        if len(lStr)==10 or len(lStr)==20:
            tStr = lStr[0:10]
            if not tStr in str10Counts:
                str10Counts[tStr] = 0
            str10Counts[tStr] += 1
    candidates = []
    for lStr,c in str10Counts.items():
        if c<2:
            continue
        candidates.append(lStr)
    if len(candidates)>1:
        print('found {} possible candidates'.format(len(candidates)))
    return candidates[0] if len(candidates)==1 else None


def extractRC4Key(soFile, encContentSample=None):
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
            blockStart,blockEnd = findLegalHexStrBlock(dataContent,pkgIdx)
            if blockStart>-1 and blockEnd>-1:
                keyStr = dataContent[blockStart:blockEnd].replace(b'\x00',b'').decode('utf-8')
                if blockEnd == pkgIdx:
                    dFmt = '<I' if littleEndian else '>I'
                    keyIdx = [struct.unpack(dFmt, dataContent[i:i+4])[0] for i in range(0,20*4,4)]
                else:  #旧版本的没有libsec中位置略有变化  
                    keyIdx = findBestMatchKeyIdx(dataContent,keyStr, blockStart, encContentSample ,littleEndian=littleEndian)
    #print(keyIdx)
    #print(keyStr)
    return ''.join([keyStr[idx] for idx in keyIdx]) if keyStr else None

def getPreKey(rawKey,keyIdxArr):
    return ''.join([rawKey[idx] for idx in keyIdxArr])

def computeRC4KeyState(rc4Key, initialState=None):
    preKey = rc4Key
    if rc4Key is None or isinstance(rc4Key,tuple):
        preKey = getPreKey(rc4Key[0] if rc4Key else None,rc4Key[1] if rc4Key else None)
    stateSize = len(initialState) if initialState else 256
    keyLen = len(preKey)
    blockA = [ord(preKey[i%keyLen]) for i in range(stateSize)]
    blockB = [a for a in initialState] if initialState else [i for i in range(stateSize)]
    si = 0
    for i in range(stateSize):
        si = (si + blockA[i] + blockB[i]) % stateSize
        blockB[i], blockB[si] = blockB[si], blockB[i]
    return blockB

def decrypt(dataBytes,rc4Key, initialState=None):
    #use pycryptodome library to speed up decryption
    ''''''
    global CRYPTODOME_ARC4
    if not initialState and CRYPTODOME_ARC4:
        # Object type <type 'unicode'> cannot be passed to C code
        rc4Instance = CRYPTODOME_ARC4.new(rc4Key.encode('utf-8') if isinstance(rc4Key,unicode) else rc4Key)
        return rc4Instance.decrypt(dataBytes)
    
    decDataBytes = [0] * len(dataBytes)
    keyState = computeRC4KeyState(rc4Key,initialState=initialState)
    stateSize = len(keyState)
    R3,R4 = 0, 0
    for i in range(len(dataBytes)):
        R3 = (R3 + 1) % stateSize
        R4 = (R4 + keyState[R3]) % stateSize
        keyState[R3], keyState[R4] = keyState[R4], keyState[R3] 
        sIdx = (keyState[R3] + (keyState[R4] % stateSize)) % stateSize
        decDataBytes[i] ^= (ord(dataBytes[i]) ^ keyState[sIdx]) & 0xFF

    return bytes(bytearray(decDataBytes)) if isinstance(dataBytes,bytes) else bytearray(decDataBytes) if isinstance(dataBytes,bytearray) else decDataBytes

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
                    if ord(elfHeader[1])==ord('E') and ord(elfHeader[2])==ord('L') and ord(elfHeader[3])==ord('F'):
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
                
                encSampleBytes = None
                if isResourceEncrypted(apkFilePath):
                    minAssetName, maxAssetName = findSmallestAndBiggestEncryptedAsset(apkFilePath)
                    if minAssetName:
                        with apkFile.open(minAssetName,'r') as encAsset:
                            encSampleBytes = encAsset.read()
                rc4Key = extractRC4Key(soContent, encContentSample=encSampleBytes)
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
            if not (resName.startswith('assets/widget/') and needDecryptFile(resName)):
                continue
            yield resName,apkFile.open(resName)

def findSmallestAndBiggestEncryptedAsset(apkFilePath):
    if not os.path.exists(apkFilePath):
        print('{} does not exists'.format(apkFilePath))
        return None, None
    minSize, maxSize = 1<<32, -1
    minInfoName, maxInfoName = None, None
    with zipfile.ZipFile(apkFilePath) as apkFile:
        for zInfo in apkFile.infolist():
            if zInfo.file_size<1:
                continue
            if not (zInfo.filename.startswith('assets/widget/') and needDecryptFile(zInfo.filename)):
                continue
            if zInfo.file_size<minSize:
                minSize = zInfo.file_size
                minInfoName = zInfo.filename
            if zInfo.file_size>maxSize:
                maxSize = zInfo.file_size
                maxInfoName = zInfo.filename
    return minInfoName, maxInfoName

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
            decContent = decrypt(rawContent,rc4Key=rc4Key) if resEncrypted and isVeryLikelyEncrypted(rawContent)  else rawContent
            fileContent.close()
            resDecrypted = file_util.legimateFileName('{}/{}'.format(storeFolder,fName))
            decryptMap[fName] = resDecrypted 
            file_util.createDirectoryIfNotExist(resDecrypted)
            with open(resDecrypted,'wb') as f:
                f.write(decContent)
            if printLog:
                sys.stdout.write('decrypt {}\r'.format(fName))
                sys.stdout.flush()
        if printLog:
            print(u'completed\n')

    return decryptMap


def _decryptHandle(fName,rawContent,rc4Key,resEncrypted,msgQueue):
    decContent = decrypt(rawContent,rc4Key) if resEncrypted and isVeryLikelyEncrypted(rawContent)  else rawContent 
    msgQueue.put_nowait((fName,decContent))

def decryptAllResourcesInApkParallel(apkFilePath,saveTo=None,printLog=False,procPool=None,msgQueue=None):
    resEncrypted,rc4Key = isResourceEncrypted(apkFilePath),None
    if resEncrypted:
        rc4Key = extractRC4KeyFromApk(apkFilePath)
        if not rc4Key:
            if printLog:
                print(u'fail to extract rc4 key')
            return None
    #print('decryptAllResourcesInApkParallel',apkFilePath,resEncrypted,rc4Key,type(rc4Key))
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
                if resEncrypted:
                    procPool.apply_async(_decryptHandle,args=(fName,rawContent,rc4Key,resEncrypted,msgQueue))
                else:
                    msgQueue.put_nowait((fName,rawContent))
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
            resDecrypted = file_util.legimateFileName('{}/{}'.format(storeFolder,fName))
            decryptMap[fName] = resDecrypted 
            file_util.createDirectoryIfNotExist(resDecrypted)
            with open(resDecrypted,'wb') as f:
                f.write(decContent)
            if printLog:
                sys.stdout.write('{}/{}  decrypt {}\r'.format(globalStates['processedFiles'],globalStates['submittedFiles'],fName))
                sys.stdout.flush()
        if printLog:
            print(u'completed\n')

    return decryptMap  