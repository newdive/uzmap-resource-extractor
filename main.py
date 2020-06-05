#coding=utf-8
#created by SamLee 2020/3/6
import sys
import os
import zipfile
import optparse
import tools
import time

if sys.version_info[0] < 3:
    print(u"当前的Python版本: {}。该程序只能在Python3.x下运行。".format(sys.version.split(' ')[0]))
    sys.exit(1)

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-o','--output',
        action='store',dest='output', 
        help='提取文件存放的目录(默认存放到apk所在的目录下)',default='')
    parser.add_option('-v','--viewInfo',
        action='store_true',dest='viewInfo',
        help='查看rc4的key等信息',default=False)

    options,args = parser.parse_args()
    #print(options)
    #print(args)
    if not args :
        print('没有指定apk文件/文件夹')
        sys.exit()
    if args[0] and not os.path.exists(args[0]) :
        print('没有指定apk文件/文件夹')
        sys.exit()
    if args[0] and not os.path.isdir(args[0]) and not zipfile.is_zipfile(args[0]):
        print('{} 不是apk文件'.format(args[0]))
        sys.exit()

    if options.viewInfo:
        apkInfos = tools.extractAPICloudApkInfos(args[0],True)
        for apk,apkInfo in apkInfos.items():
            print(apk)
            print('\tpackage      : {}\n\tuz_version   : {}\n\tencrypted    : {}\n\trc4Key       : {}\n'.format(apkInfo['package'], \
                                                                        apkInfo['uz_version'], \
                                                                        apkInfo['encrypted'], \
                                                                        apkInfo['resKey']))
        print('共找到 {} 个 apicloud apk'.format(len(apkInfos)))
    else:
        outputFolder = options.output
        startTime = time.time()
        extractMap = tools.decryptAndExtractAPICloudApkResources(args[0],outputFolder,printLog=True)
        print('耗时 : {} 秒'.format(time.time()-startTime))