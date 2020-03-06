#coding=utf-8
#created by SamLee 2020/3/6
import sys
import os
import zipfile
import optparse
import tools

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-o','--output',
        action='store',dest='output', 
        help='提取文件存放的目录(默认存放到apk所在的目录下)',default=False)
    parser.add_option('-v','--viewKey',
        action='store_true',dest='viewKey',
        help='查看rc4的key',default=False)
    
    options,args = parser.parse_args()
    #print(options)
    #print(args)
    if not args:
        print('没有指定apk文件')
        sys.exit()
    if not zipfile.is_zipfile(args[0]):
        print('{} 不是apk文件'.format(args[0]))
        sys.exit()
    if options.viewKey:
        rc4Key = tools.extractRC4KeyFromApk(args[0])
        if rc4Key:
            print(rc4Key)
    else:
        outputFolder = options.output
        extractMap = tools.decryptAllResourcesInApk(args[0],outputFolder,printLog=True)
