import math
import zlib
import collections

'''
for 256 values in a byte, the maximum entropy is log2(256)/256*256 = 8 
this method is a bit slow though
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
        dataBytes = bytes(dataBytes)

    e = float(float(len(zlib.compress(dataBytes, 9))) / float(len(dataBytes)))

    return min(e,1.0)

