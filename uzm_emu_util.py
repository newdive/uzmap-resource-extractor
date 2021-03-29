import os
import sys
import zipfile
import tempfile
import time
from emu_support import uzm_emu
from Crypto.Cipher import ARC4
import traceback
import multiprocessing
import threading
import apk_util
import dex_util
import file_util


enc_exts = ['js','html','css']
def needDecryptFile(fileName):
    global enc_exts
    extIdx = fileName.rfind('.')
    ext = fileName[extIdx+1:] if extIdx>-1 else None
    return  ext in enc_exts or 'config.xml' in fileName or 'key.xml' in fileName

def isResourceEncrypted(apkFilePath):
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


def iterateAllNeedDecryptAssets(apkFilePath, limit=-1, sortKey=None, desc=False,
                                yieldRawContent=False):
    if not os.path.exists(apkFilePath):
        print('{} does not exists'.format(apkFilePath))
        return

    with zipfile.ZipFile(apkFilePath) as apkFile:
        encApkResList = [info for info in apkFile.infolist() if info.filename.startswith('assets/widget/') and needDecryptFile(info.filename)]
        if sortKey and hasattr(encApkResList[0], sortKey):
            encApkResList = sorted(encApkResList, key=lambda v:getattr(v,sortKey))
            if desc:
                encApkResList = [info for info in reversed(encApkResList)]
        yieldCount, yieldLimit = 0, limit if limit>0 else len(encApkResList)
        while yieldCount < yieldLimit:
            resName = encApkResList[yieldCount].filename
            if yieldRawContent:
                with apkFile.open(resName) as apkItem:
                    yield resName, apkItem.read()
            else:
                yield resName, apkFile.open(resName)
            yieldCount += 1


def getUzmAppInfo(apkFilePath):
    apicloudInfo = None
    try:
        apicloudInfo = apk_util.extractAPICloudInfo(apkFilePath)
    except:
        print('error while extracting apk info from {}'.format(apkFilePath))
        traceback.print_exc()
    return apicloudInfo if 'package' in apicloudInfo else None


def isOlderVersion(apkFilePath, appInfo=None):
    apicloudInfo = appInfo
    if not apicloudInfo:
        try:
            apicloudInfo = apk_util.extractAPICloudInfo(apkFilePath)
        except:
            print('error while extracting apk info from {}'.format(apkFilePath))
            traceback.print_exc()
    # for older version 1.2.0
    if not apicloudInfo or apk_util.APICLOUD_MANIFEST_APPVERSION not in apicloudInfo:
        return True
    versionStr = apicloudInfo[apk_util.APICLOUD_MANIFEST_APPVERSION]
    vParts = [int(a) for a in versionStr.split('.')]
    return not ((vParts[0] == 1 and vParts[1] >= 2) or vParts[0] > 1)


def readLibSecSoContent(apkFilePath):
    soContentArr = []
    with zipfile.ZipFile(apkFilePath) as apkFile:
        apkResList = apkFile.namelist()
        for fname in apkResList:
            if not (fname.startswith('lib/') and fname.endswith('libsec.so')):
                continue
            with apkFile.open(fname) as soFile:
                soContent = soFile.read()
                elfHeader = soContent[0:6]
                #check elffile format(https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
                if elfHeader[1] == ord('E') and elfHeader[2] == ord('L') and elfHeader[3] == ord('F'):
                    soContentArr.append(soContent)

    return soContentArr[0] if len(soContentArr)>0 else None


def readInfoForEmuFromApk(apkFilePath):
    appInfo = getUzmAppInfo(apkFilePath)
    signatureBytesArr = apk_util.extractAllApkSignatureBytes(apkFilePath)
    if not signatureBytesArr:
        print('fail to read signature bytes from {}'.format(apkFilePath))
    soContent = readLibSecSoContent(apkFilePath)
    if soContent is None:
        print('fail to read libsec.so from {}'.format(apkFilePath))
    return appInfo, signatureBytesArr[0] if signatureBytesArr else None, soContent

# use cached context to avoid slow start of emulator every time
EmuContextCached = {}
def getCachedEmuContextFromApkFile(apkFilePath):
    global EmuContextCached
    if apkFilePath in EmuContextCached:
        return EmuContextCached[apkFilePath]
    appInfo, signatureBytes, soContent = readInfoForEmuFromApk(apkFilePath)
    if not appInfo or not signatureBytes or not soContent:
        print('can not read all necessary info for emulation')
        return None
    appName = appInfo['package']
    ctx = uzm_emu.UZMEmuContext(appName, signatureBytes, soContent)
    EmuContextCached[apkFilePath] = ctx
    return ctx


def isApkResourceEncryptedByRC4(apkFilePath):
    if not isResourceEncrypted(apkFilePath):
        return False
    if isOlderVersion(apkFilePath):
        return True
    ctx = getCachedEmuContextFromApkFile(apkFilePath)
    if ctx is None:
        return False
    assetBytesArr = list(iterateAllNeedDecryptAssets(apkFilePath, limit=2, sortKey='file_size', yieldRawContent=True))
    return uzm_emu.isUsingRC4EncryptionFromCtx(ctx, assetBytesArr[0][1], assetBytesArr[1][1])


def extractRC4KeyFromApk(apkFilePath):
    ctx = getCachedEmuContextFromApkFile(apkFilePath)
    if ctx is None:
        return None
    assetBytesArr = list(iterateAllNeedDecryptAssets(apkFilePath, limit=1, sortKey='file_size', yieldRawContent=True))
    rc4KeyCandidates, decBytes = uzm_emu.tryGetRC4KeyFromCtx(ctx, assetBytesArr[0][1])
    if not rc4KeyCandidates:
        print('No key candidate found duration emulation.Maybe the codeflow is changed!')
        return None
    for key in rc4KeyCandidates:
        rc4Cipher = ARC4.new(key.encode('utf-8'))
        # must validate decrypted result by rc4 cipher
        if rc4Cipher.decrypt(assetBytesArr[0][1]) == decBytes:
            return key
    print('Cannot find any valid rc4 key. Maybe not using the general rc4 algorithm or not using rc4 encryption at all!')
    return None


def _decryptResource(apkFilePath, resName, rawContent, isRc4Encrypted, rc4Key, rc4KeyStream, msgQueue):
    decContent = rawContent
    try:
        if isRc4Encrypted:
            if rc4Key:
                cipher = ARC4.new(rc4Key.encode('utf-8'))
                decContent = cipher.decrypt(rawContent)
            elif rc4KeyStream is not None:
                import numpy as np
                decContent = bytes(rc4KeyStream[0:len(rawContent)] ^ np.frombuffer(rawContent, 'uint8'))
        else:
            ctx = getCachedEmuContextFromApkFile(apkFilePath)
            decContent = uzm_emu.decryptFromCtx(ctx, rawContent)
    except:
        traceback.print_exc()
    msgQueue.put_nowait((resName, decContent))


def decryptAllResourcesInApk(apkFilePath, saveTo):
    isRc4Encrypted = isApkResourceEncryptedByRC4(apkFilePath)
    rc4Key, rc4KeyStream = extractRC4KeyFromApk(apkFilePath), None
    if isRc4Encrypted and not rc4Key:
        assets = list(iterateAllNeedDecryptAssets(apkFilePath, limit=1, sortKey='file_size', desc=True,
                                             yieldRawContent=True))
        rc4KeyStream = uzm_emu.getRC4KeyStreamFromCtx(getCachedEmuContextFromApkFile(apkFilePath), assets[0][1])
        print('try use rc4 keyStream to decrypt')
    storeFolder = os.path.dirname(os.path.abspath(apkFilePath))
    saveTo = saveTo.strip()
    if saveTo:
        if not os.path.exists(saveTo):
            os.makedirs(saveTo)
        storeFolder = saveTo
    procPool = multiprocessing.Pool(processes=max(2, multiprocessing.cpu_count()))
    msgQueue = multiprocessing.Manager().Queue(0)
    allAssets = iterateAllNeedDecryptAssets(apkFilePath, yieldRawContent=True)

    def subHandle(apkFilePath, allAssets, isRc4Encrypted, rc4Key, rc4KeyStream, procPool, msgQueue, globalStates):
        while True:
            assetFile = next(allAssets, None)
            if not assetFile:
                break
            resName, fileContent = assetFile
            procPool.apply_async(_decryptResource, args=(apkFilePath, resName, fileContent,
                                                         isRc4Encrypted, rc4Key, rc4KeyStream, msgQueue))
            globalStates['submittedFiles'] += 1
        globalStates['submitCompleted'] = True

    decryptMap = {}
    globalStates = {'submittedFiles':0, 'processedFiles':0, 'submitCompleted':False}
    subTh = threading.Thread(target=subHandle,
                             args=(apkFilePath, allAssets,
                                   isRc4Encrypted, rc4Key, rc4KeyStream,
                                   procPool, msgQueue, globalStates))
    subTh.start()
    while True:
        if globalStates['submitCompleted'] and globalStates['processedFiles'] >= globalStates['submittedFiles']:
            break
        if msgQueue.empty():
            time.sleep(0.01)
            continue
        resName, decContent = msgQueue.get_nowait()
        globalStates['processedFiles'] += 1
        msgQueue.task_done()
        resDecrypted = file_util.legimateFileName('{}/{}'.format(storeFolder, resName))
        decryptMap[resName] = resDecrypted
        file_util.createDirectoryIfNotExist(resDecrypted)
        with open(resDecrypted, 'wb') as f:
            f.write(decContent)
        sys.stdout.write('{}/{}  decrypt {}\r'.format(globalStates['processedFiles'],
                                                      globalStates['submittedFiles'],
                                                      resName))
        sys.stdout.flush()

    return decryptMap
