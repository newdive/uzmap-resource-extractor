#coding=utf-8
#created by SamLee 2020/6/12

import os
import sys

Windows_ForbiddenFileChars = set(['?',':','*','<','>','|','"','\\'])
Windows_ReservedFilenames = set(['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'])

'''
windows上有些预留的字符，单词不能作为文件名 需要避免
处理方式是将这些不合法字符转化成url-escape形式的字符串 
'''
def legimateFileName(originalFileName):
    global Windows_ReservedFilenames,Windows_ForbiddenFileChars
    transformedFileName = originalFileName

    if 'win' in sys.platform.lower():
        dirName,baseFileName = os.path.dirname(originalFileName), os.path.basename(originalFileName)
        extIdx = baseFileName.find('.')
        if extIdx!=-1 and baseFileName[0:extIdx].upper() in Windows_ReservedFilenames:
            baseFileName = '{}{}'.format(''.join(['%{:X}'.format(ord(c)) for c in baseFileName[0:extIdx]]),baseFileName[extIdx:])
        baseFileName = ''.join(['%{:X}'.format(ord(c)) if c in Windows_ForbiddenFileChars else c  for c in baseFileName])
        transformedFileName = '{}/{}'.format(dirName,baseFileName)

    return transformedFileName


def createDirectoryIfNotExist(targetFile):
    fParent = os.path.dirname(targetFile)
    if fParent and not os.path.exists(fParent):
        os.makedirs(fParent)