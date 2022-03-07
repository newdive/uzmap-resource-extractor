# -*- coding: UTF-8 -*-
from unicorn import UcError, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import *
import unicorn

import sys
import posixpath
import time
import os
#sys.path.append(os.path.abspath('./AndroidNativeEmu'))
import logging
import shutil
import tempfile
import types

scriptDir = os.path.dirname(__file__)
# make sure that androidemu in search path
if not os.path.join(scriptDir,'AndroidNativeEmu') in sys.path:
    sys.path.append(os.path.join(scriptDir,'AndroidNativeEmu'))
#.AndroidNativeEmu.
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def
from samples import debug_utils
from androidemu.utils import memory_helpers
import traceback


class Signature(metaclass=JavaClassDef, jvm_name='android/content/pm/Signature'):
    def __init__(self, sigBytes):
        self.sigBytes = sigBytes

    @java_method_def(name='toByteArray', signature='()[B', native=False)
    def toByteArray(self, emu):
        barr = bytearray(self.sigBytes)
        return barr


class PackageInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageInfo', 
                    jvm_fields=[
                        #JavaFieldDef('applicationInfo', 'Landroid/content/pm/ApplicationInfo;', False),
                        JavaFieldDef('firstInstallTime', 'J', False),
                        JavaFieldDef('lastUpdateTime', 'J', False),
                        JavaFieldDef('signatures', '[Landroid/content/pm/Signature;', False)
                    ]):
    def __init__(self, pyPkgName, sigBytesArr=None):
        #self.applicationInfo = ApplicationInfo(pyPkgName)
        self.firstInstallTime = int(time.time())
        self.lastUpdateTime = self.firstInstallTime
        if sigBytesArr:
            self.signatures = [Signature(sigBytes) for sigBytes in sigBytesArr] #jni_ref.jobjectArray()
        else:
            self.signatures = []


class PackageManager(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageManager'):
    def __init__(self, pyPkgName, sigBytesArr=None):
        if sigBytesArr:
            if isinstance(sigBytesArr, (bytes, bytearray)):
                sigBytesArr = [sigBytesArr]
        self.__pkg_info = PackageInfo(pyPkgName, sigBytesArr=sigBytesArr)

    @java_method_def(name='getPackageInfo', signature='(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;', native=False)
    def getPackageInfo(self, emu):
        return self.__pkg_info


class Context(metaclass=JavaClassDef, jvm_name='android/content/Context',
                 jvm_fields=[
                     JavaFieldDef('WIFI_SERVICE', 'Ljava/lang/String;', True, "wifi")
                 ]):
    def __init__(self):
        pass
    


class ContextImpl(Context, metaclass=JavaClassDef, jvm_name='android/app/ContextImpl', jvm_super=Context):
    def __init__(self, packageName, signatureBytes):
        Context.__init__(self)
        self.__pkgName = packageName
        self.__pkg_mgr = PackageManager(packageName, sigBytesArr=signatureBytes)


    @java_method_def(name='getPackageManager', signature='()Landroid/content/pm/PackageManager;', native=False)
    def getPackageManager(self, emu):
        return self.__pkg_mgr

    @java_method_def(name='getPackageName', signature='()Ljava/lang/String;', native=False)
    def getPackageName(self, emu):
        return self.__pkgName


class ContextWrapper(Context, metaclass=JavaClassDef, jvm_name='android/content/ContextWrapper', jvm_super=Context):

    def __init__(self):
        Context.__init__(self)
        self.__impl = None

    def attachBaseContext(self, ctx_impl):
        self.__impl = ctx_impl

    @java_method_def(name='getPackageManager', signature='()Landroid/content/pm/PackageManager;', native=False)
    def getPackageManager(self, emu):
        return self.__impl.getPackageManager(emu)

    @java_method_def(name='getPackageName', signature='()Ljava/lang/String;', native=False)
    def getPackageName(self, emu):
        return self.__impl.getPackageName(emu)


class Enslecb(metaclass=JavaClassDef, jvm_name='com/uzmap/pkg/uzcore/external/Enslecb'):
    def __init__(self):
        pass

    @java_method_def(name='sm', signature='(Ljava/lang/Object;)Z', native=True)
    def sm(self, mu):
        pass

    # 调用这个方法的时候 第二个参数必须传null , 但由于底层不支持None参数, 所以传送 0 代表null
    @java_method_def(name='ohs', signature='([BLjava/lang/String;)[B', native=True)
    def ohs(self, mu):
        pass

    @java_method_def(name='oc', signature='(Ljava/lang/Object;)Ljava/lang/String;', native=True)
    def oc(self, mu):
        pass


def prepareEmulator(jniClasses):
    global scriptDir
    posixpath.join(scriptDir, "vfs")
    emulator = Emulator(
        vfp_inst_set=True,
        vfs_root=posixpath.join(scriptDir, "AndroidNativeEmu/samples/vfs")
    )
    for jniClass in jniClasses:
        emulator.java_classloader.add_class(jniClass)

    emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
    emulator.load_library(posixpath.join(scriptDir, "AndroidNativeEmu/samples/example_binaries/libc.so"),do_init=False)
    emulator.load_library(posixpath.join(scriptDir, "AndroidNativeEmu/samples/example_binaries/libdl.so"),do_init=False)
    return emulator


# enable 'with' syntax
class UZMEmuContext:
    def __init__(self, appName, appSignatureBytes, soFile, showDetailLog=False):
        self.emulator = prepareEmulator([Enslecb])
        _soTemp = None
        if not isinstance(soFile, str) or not os.path.exists(soFile):
            tmpDir = os.getcwd()
            _soTemp = self._copySoContent(soFile, tmpDir)
            soFile = _soTemp[1]
        self.soModule = self.emulator.load_library(soFile)
        if _soTemp:
            os.close(_soTemp[0])
            os.remove(_soTemp[1])
        # create application instance
        self.appInstance = ContextWrapper()
        self.appInstance.attachBaseContext(ContextImpl(appName, appSignatureBytes))
        self.jniInterface = Enslecb()
        self.libcModule = None
        self._jniInited = False
        self.logger = None
        if showDetailLog:
            logging.basicConfig(
                stream=sys.stdout,
                level=logging.DEBUG,
                format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
            )
            self.logger = logging.getLogger(__name__)

    def _copySoContent(self, soFile, targetDir):
        _soTemp = tempfile.mkstemp('.tmp.so', 'tmp', targetDir)
        with open(_soTemp[1], 'wb') as soTempF:
            if not hasattr(soFile, 'read'):
                soTempF.write(soFile)
                return _soTemp
            shutil.copyfileobj(soFile, soTempF)
            if hasattr(soFile, 'close'):
                try:
                    soFile.close()
                except:pass
        return _soTemp

    def getLibcModule(self):
        if not self.libcModule:
            for module in self.emulator.modules:
                if module.filename.endswith('libc.so'):
                    self.libcModule = module
                    break
        return self.libcModule

    def doJniInit(self):
        if self._jniInited:
            return
        try:
            self.emulator.call_symbol(self.soModule, 'JNI_OnLoad', self.emulator.java_vm.address_ptr, 0x00)
            smResult = self.jniInterface.sm(self.emulator, self.appInstance)
            self._jniInited = True
        except Exception as e:
            traceback.print_exc()

    def __enter__(self):
        # initialize 
        # in actual android app, this is invoked in onCreate method of Application
        self.doJniInit()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def tryGetRC4KeyFromCtx(uzmCtx, encRawBytes):
    with uzmCtx:
        strLenAddress, rc4KeyCandidates = None, []
        def hookCode(mu,address,size,userdata):
            nonlocal strLenAddress, rc4KeyCandidates
            if strLenAddress is not None and address == strLenAddress:
                r0Value = mu.reg_read(UC_ARM_REG_R0)
                rc4KeyCandidates.append(memory_helpers.read_utf8(mu, r0Value) )
        # every time we call ohs
        # it will invoke strlen function to get the length of rc4Key
        # so we can intercept rc4Key by hooking the strlen function
        strLenSymbol = uzmCtx.getLibcModule().find_symbol("strlen")
        strLenAddress = strLenSymbol.address - 1  # thumb elf , odd address
        hookHandle = uzmCtx.emulator.mu.hook_add(unicorn.UC_HOOK_CODE, hookCode)
        if isinstance(encRawBytes, bytes):
            encRawBytes = bytearray(encRawBytes)
        ohsResult = uzmCtx.jniInterface.ohs(uzmCtx.emulator, encRawBytes, 0)
        uzmCtx.emulator.mu.hook_del(hookHandle)
        return rc4KeyCandidates, bytes(ohsResult)


def tryGetRC4Key(appName, appSignatureBytes, soFile, encRawBytes):
    with UZMEmuContext(appName, appSignatureBytes, soFile) as ctx:
        return tryGetRC4KeyFromCtx(ctx, encRawBytes)


def getUzmOcKeyFromApk(appName, appSignatureBytes, soFile):
    with UZMEmuContext(appName, appSignatureBytes, soFile) as ctx:
        ocResult = ctx.jniInterface.oc(ctx.emulator, ctx.appInstance)
        return ocResult


def decryptFromCtx(uzmCtx, encBytes):
    with uzmCtx:
        if isinstance(encBytes, bytes):
            encBytes = bytearray(encBytes)
        if not encBytes:
            return b''  # return empty bytes
        ohsResult = uzmCtx.jniInterface.ohs(uzmCtx.emulator, encBytes, 0)
        return bytes(ohsResult)


def callDecryptGenFromCtx(uzmCtx, encBytesIn):
    with uzmCtx:
        while True:
            encBytes = next(encBytesIn,None)
            if encBytes is None:
                break
            if isinstance(encBytes, bytes):
                encBytes = bytearray(encBytes)
            if not encBytes:
                yield b''  # return empty bytes
            else:
                ohsResult = uzmCtx.jniInterface.ohs(uzmCtx.emulator, encBytes, 0)
                yield bytes(ohsResult)

# if encryption algorithm , just call this  treat it as a black box
# this could be slow  and should only be treated as last resort
def callDecryptGen(appName, appSignatureBytes, soFile, encBytesIn):
    with UZMEmuContext(appName, appSignatureBytes, soFile) as ctx:
        return callDecryptGenFromCtx(ctx, encBytesIn)


def __xorBytes(bytesA, bytesB):
    import numpy as np
    if not isinstance(bytesA, bytes):
        bytesA = bytes(bytesA)
    if not isinstance(bytesB, bytes):
        bytesB = bytes(bytesB)
    return np.frombuffer(bytesA, 'uint8') ^ np.frombuffer(bytesB, 'uint8')


def isUsingRC4EncryptionFromCtx(ctx, encBytesA, encBytesB):
    with ctx:
        decBytesA = ctx.jniInterface.ohs(ctx.emulator, encBytesA if isinstance(encBytesA, bytearray) else bytearray(encBytesA), 0)
        decBytesB = ctx.jniInterface.ohs(ctx.emulator, encBytesB if isinstance(encBytesB, bytearray) else bytearray(encBytesB), 0)
        if not decBytesA or not decBytesB:
            return False
        if len(decBytesA) != len(encBytesA) or len(decBytesB) != len(encBytesB):
            return False
        minLen = min(len(decBytesA), len(decBytesB))
        if len(decBytesA) > minLen:
            decBytesA, encBytesA = decBytesA[0:minLen], encBytesA[0:minLen]
        if len(decBytesB) > minLen:
            decBytesB, encBytesB = decBytesB[0:minLen], encBytesB[0:minLen]
        keyStreamA = __xorBytes(decBytesA, encBytesA)
        keyStreamB = __xorBytes(decBytesB, encBytesB)
        return (keyStreamA == keyStreamB).all()


# since rc4 encrypt keyStream will always be the same
# so we can use xor method of encrypted bytes and decrypted bytes to get the desired keyStream
# and then compare the two keyStream to check if they have the same prefix
def isUsingRC4Encryption(appName, appSignatureBytes, soFile, encBytesA, encBytesB):
    with UZMEmuContext(appName, appSignatureBytes, soFile) as ctx:
        return isUsingRC4EncryptionFromCtx(ctx, encBytesA, encBytesB)


def getRC4KeyStreamFromCtx(ctx, encBytes):
    with ctx:
        decBytes = ctx.jniInterface.ohs(ctx.emulator, encBytes if isinstance(encBytes, bytearray) else bytearray(encBytes), 0)
        return __xorBytes(decBytes, encBytes)
