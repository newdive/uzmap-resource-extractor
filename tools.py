#coding=utf-8
#created by SamLee 2020/6/5

import os
import sys
import multiprocessing
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import datetime
import apk_util
import uzm_util

def determineSavePath(apkPath,saveTo):
    saveTo = saveTo.strip()
    apkPath = os.path.abspath(apkPath)
    apkName = os.path.basename(apkPath)
    if not saveTo:
        saveTo = os.path.dirname(apkPath)
    if '.' in apkName:
        apkName = apkName[0:apkName.rfind('.')]
    saveApkPath = '{}/{}'.format(saveTo,apkName)
    #in order to avoid conflict , add a timestamp to saveApkPath
    if os.path.exists(saveApkPath):
        saveApkPath = '{}_{}'.format(saveApkPath,datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
    return saveApkPath

'''
旧api
对apicloud的apk进行资源的解密提取 
'''
def decryptAllResourcesInApk(apkFilePath,saveTo=None,printLog=False):
    return uzm_util.decryptAllResourcesInApk(apkFilePath,determineSavePath(apkFilePath,saveTo),printLog)

'''
旧api
查看apicloud的apk的资源密钥
'''
def extractRC4KeyFromApk(apkFilePath):
    return uzm_util.extractRC4KeyFromApk(apkFilePath)



def extractAPICloudApkInfo(resourcePath,extractRC4Key=False,msgQueue=None,isDefaultApk=False):
    apicloudInfo = apk_util.extractAPICloudInfo(resourcePath,isDefaultApk)
    if apicloudInfo and extractRC4Key:
        apicloudInfo['resKey'] = uzm_util.extractRC4KeyFromApk(resourcePath)
        apicloudInfo['encrypted'] = uzm_util.isResourceEncrypted(resourcePath)
    if msgQueue:
        msgQueue.put_nowait((resourcePath,apicloudInfo))
    return resourcePath,apicloudInfo

def _decryptAPICloudApkResources(apkFilePath,saveTo,msgQueue=None,printLog=False):
    decMap = uzm_util.decryptAllResourcesInApk(apkFilePath,saveTo,printLog)
    if msgQueue:
        msgQueue.put_nowait((apkFilePath,saveTo,decMap))
    return apkFilePath,saveTo,decMap

def _decryptAPICloudApkResourcesParallel(apkFilePath,saveTo,procPool=None,msgQueue=None,printLog=False):
    decMap = uzm_util.decryptAllResourcesInApkParallel(apkFilePath,saveTo,printLog,procPool=procPool)
    if msgQueue:
        msgQueue.put_nowait((apkFilePath,saveTo,decMap))
    return apkFilePath,saveTo,decMap

def _scanAPICloudApks(procPool,msgQueue,resourcePath,extractRC4Key=False,printLog=False):

    def scanHandle(procPool,msgQueue,resourcePath,extractRC4Key,globalStates):
        for root, dirs, files in os.walk(resourcePath):
            for f in files:
                procPool.apply_async(extractAPICloudApkInfo,args=('{}/{}'.format(root,f),extractRC4Key,msgQueue)) 
                globalStates['submittedFiles'] += 1
        globalStates['scanComplete'] = True
    
    globalStates = {'submittedFiles':0,'scanComplete':False,'processedFiles':0}

    scanTh = threading.Thread(target=scanHandle,args=(procPool,msgQueue,resourcePath,extractRC4Key,globalStates))
    scanTh.start()
    
    apkInfoMap = {}
    while True:
        if globalStates['scanComplete'] and globalStates['submittedFiles']<=globalStates['processedFiles']:
            break
        if msgQueue.empty():
            time.sleep(0.01)
            continue
        apkPath,apkInfo = msgQueue.get_nowait()
        globalStates['processedFiles'] += 1
        if apkInfo:
            apkInfoMap[apkPath] = apkInfo
        msgQueue.task_done()
        if printLog:
            sys.stdout.write('{}/{}  => {}\r'.format(globalStates['processedFiles'],globalStates['submittedFiles'],apkPath))
            sys.stdout.flush()
    if printLog:
        print('\n')
    return apkInfoMap
    
def _decryptAPICloudApks(procPool,msgQueue,apkInfoMap,saveTo,printLog=False):
 
    totalApks = len(apkInfoMap)
    decApkMap = {}
    for apkPath,apkInfo in apkInfoMap.items():
        if printLog:
            print(apkPath)
        saveApkPath = determineSavePath(apkPath,saveTo)
        decMap = uzm_util.decryptAllResourcesInApkParallel(apkPath,saveApkPath,printLog,procPool=procPool,msgQueue=msgQueue)
        decApkMap[apkPath] = (saveApkPath,decMap)
        if printLog:
            print('\t=>{}'.format(saveApkPath))
            print('\t{} files decrypted.'.format(len(decMap)))
            print('\n')
    return decApkMap

'''
resourcePath 可以是apk的路径， 也可以apk所在的目录
如果是目录，则会扫描所有可能的apicloud apk，并进行信息的提取
'''
def extractAPICloudApkInfos(resourcePath,printLog=False):
    if not os.path.isdir(resourcePath):
        _,apicloudInfo = extractAPICloudApkInfo(resourcePath,True)
        return {resourcePath:apicloudInfo} if apicloudInfo else {}

    msgQueue = multiprocessing.Manager().Queue(0)
    procPool = multiprocessing.Pool(processes=max(2, multiprocessing.cpu_count() ) ) 

    apkInfoMap = _scanAPICloudApks(procPool,msgQueue,resourcePath,True,printLog=printLog)
    try:
        procPool.close()
        procPool.join()
    except:pass

    return apkInfoMap
'''
resourcePath 可以是apk的路径， 也可以apk所在的目录
如果是目录，则会自动扫描并解密所有的apk, 解密后存放到 saveTo/apkName/
'''
def decryptAndExtractAPICloudApkResources(resourcePath,saveTo,printLog=False):
    if not os.path.isdir(resourcePath):
        print(determineSavePath(resourcePath,saveTo))
        return {resourcePath:uzm_util.decryptAllResourcesInApkParallel(resourcePath,determineSavePath(resourcePath,saveTo),printLog)} 

    msgQueue = multiprocessing.Manager().Queue(0)
    procPool = multiprocessing.Pool(processes=max(2, multiprocessing.cpu_count() ) ) 
    
    startTime = time.time()
    apkInfoMap = _scanAPICloudApks(procPool,msgQueue,resourcePath,False,printLog=printLog)
    scanCost = time.time()-startTime
    if not apkInfoMap:
        if printLog:
            print('no apicloud apk found')
        return {}
    
    if printLog:
        print('{} seconds elapsed.  {} apks found'.format(scanCost,len(apkInfoMap)))
    
    if len(apkInfoMap)<2:
        apkFile = list(apkInfoMap.keys())[0]
        decryptMap = {apkFile:(determineSavePath(apkFile,saveTo),uzm_util.decryptAllResourcesInApkParallel(apkFile,saveTo,printLog,procPool,msgQueue))} 
    else:
        decryptMap = _decryptAPICloudApks(procPool,msgQueue,apkInfoMap,saveTo,printLog)

    try:
        procPool.close()
        procPool.join()
    except:pass

    return decryptMap