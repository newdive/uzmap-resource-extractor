#coding=utf-8
#created by SamLee 2020/3/6
import sys
import os
import zipfile
import optparse
import tools

if sys.version_info[0] != 2:
    print(u"当前的Python版本: {}。 该程序只能在Python2.7下运行。".format(sys.version.split(' ')[0]))
    sys.exit(1)

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-o','--output',
        action='store',dest='output', 
        help = u'提取文件存放的目录(默认存放到apk所在的目录下)',default=False)
    parser.add_option('-v','--viewKey',
        action='store_true',dest='viewKey',
        help = u'查看rc4的key',default=False)
    
    options,args = parser.parse_args()
    #print(options)
    #print(args)
    if not args:
        print(u'没有指定apk文件')
        sys.exit()
    if not zipfile.is_zipfile(args[0]):
        print(u'{} 不是apk文件'.format(args[0]))
        sys.exit()
    if options.viewKey:
        rc4Key = tools.extractRC4KeyFromApk(args[0])
        if rc4Key:
            print(rc4Key)
    else:
        outputFolder = options.output
        extractMap = tools.decryptAllResourcesInApk(args[0],outputFolder,printLog=True)
