import math
import zlib
import collections
import os

'''
for 256 values in a byte, the maximum entropy is log2(256)/256*256 = 8 
this method is a bit slow though
when the length of dataBytes is less than 256  must consider maximum entropy log2(len(dataBytes))
'''
def shannonEntropy(dataBytes):
    entropy,byteValNum = 0,1
    if dataBytes:
        dataFreq = collections.Counter(dataBytes)
        length = len(dataBytes)

        for k,freq in dataFreq.items():
            p_x = float(freq)/length
            entropy -= p_x * math.log(p_x, 2)
        byteValNum = min(length,256)

    return entropy/max(1,math.log(byteValNum,2))

'''
this method is fast, in the cost of some accuracy(not as good as shanno formula)
'''
def gzipEntropy(dataBytes):
    if isinstance(dataBytes,type('')):
        dataBytes = bytes(dataBytes,'latin1')

    e = float(float(len(zlib.compress(dataBytes, 9))) / float(len(dataBytes)))

    return min(e,1.0)


def calculateEntropy(dataBytes):
    return gzipEntropy(dataBytes) if len(dataBytes)>512 else shannonEntropy(dataBytes)

def calculateFileEntropy(fileDir):
    entropyMap = {}
    if os.path.exists(fileDir):
        targetFiles = []
        if os.path.isdir(fileDir):
            for root, dirs, files in os.walk(fileDir):
                if files:
                    targetFiles.extend([os.path.join(root,f) for f in files])
        else:
            targetFiles.append(fileDir)
        
        for f in targetFiles:
            with open(f,'rb') as rf:
                fBytes = rf.read()
                entropyMap[f] = gzipEntropy(fBytes) if len(fBytes)>512 else shannonEntropy(fBytes)

    return entropyMap