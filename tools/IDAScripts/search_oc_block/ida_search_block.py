# -*- coding: utf-8 -*-

"""
Changelog:

[20231027]
1. convert to support IDA 7.4+
2. convert to Python 3.x
3. fix bug: "RecursionError: maximum recursion depth exceeded while calling a Python object"
4. output filename with app and datetime

"""

import idautils
import idc
from idaapi import PluginForm
import operator
import csv
import sys
import json

import os
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
import time

################################################################################
# Util Function
################################################################################

# def getFilenameNoPointSuffix(curFilePath):
#     """Get current filename without point and suffix

#     Args:
#         curFilePath (str): current file path. Normally can use __file__
#     Returns:
#         str, file name without .xxx
#     Raises:
#     Examples:
#         input: /Users/xxx/pymitmdump/mitmdumpOtherApi.py 
#         output: mitmdumpOtherApi
#     """
#     root, pointSuffix = os.path.splitext(curFilePath)
#     curFilenameNoSuffix = root.split(os.path.sep)[-1]
#     return curFilenameNoSuffix

def datetimeToStr(inputDatetime, format="%Y%m%d_%H%M%S"):
    """Convert datetime to string

    Args:
        inputDatetime (datetime): datetime value
    Returns:
        str
    Raises:
    Examples:
        datetime.datetime(2020, 4, 21, 15, 44, 13, 2000) -> '20200421_154413'
    """
    datetimeStr = inputDatetime.strftime(format=format)
    # print("inputDatetime=%s -> datetimeStr=%s" % (inputDatetime, datetimeStr)) # 2020-04-21 15:08:59.787623
    return datetimeStr


def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
    """
    get current datetime then format to string

    eg:
        20171111_220722

    :param outputFormat: datetime output format
    :return: current datetime formatted string
    """
    curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
    # curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
    curDatetimeStr = datetimeToStr(curDatetime, format=outputFormat)
    return curDatetimeStr

################################################################################
# Main
################################################################################

IS32BIT = not idaapi.get_inf_structure().is_64bit()

IS_MAC = 'X86_64' in idaapi.get_file_type_name()

# print "Start analyze binary for " + ("Mac" if IS_MAC else "iOS")
print("Start analyze binary for " + ("Mac" if IS_MAC else "iOS"))

idaRootFilename = get_root_filename()
print("idaRootFilename=%s" % idaRootFilename)
# idaInputFilePath = get_input_file_path()
# print("idaInputFilePath=%s" % idaInputFilePath)

# idaVersion = idaapi.IDA_SDK_VERSION
# print("idaVersion=%s" % idaVersion)

outputFilename = "block_symbol"
# outputFullFilename = "%s_%s_%s.json" % (getFilenameNoPointSuffix(__file__), outputFilename, getCurDatetimeStr())
outputFullFilename = "%s_%s_%s.json" % (idaRootFilename, outputFilename, getCurDatetimeStr())
print("outputFullFilename=%s" % outputFullFilename)


def isInText(x):
    # return SegName(x) == '__text'
    return get_segm_name(x) == '__text'


# GlobalBlockAddr = LocByName("__NSConcreteGlobalBlock")
GlobalBlockAddr = get_name_ea_simple("__NSConcreteGlobalBlock")

class GlobalBlockInfo:
    pass

AllGlobalBlockMap = {}
for struct in list(DataRefsTo(GlobalBlockAddr)):
    # func = 0L
    func = 0
    FUNC_OFFSET_IN_BLOCK = 12 if IS32BIT else 16
    if IS32BIT:
        # func = Dword(struct + FUNC_OFFSET_IN_BLOCK)
        func = get_wide_dword(struct + FUNC_OFFSET_IN_BLOCK)
    else:
        # func = Qword(struct + FUNC_OFFSET_IN_BLOCK)
        func = get_qword(struct + FUNC_OFFSET_IN_BLOCK)


    info = GlobalBlockInfo()
    info.func = func
    info.struct = struct
    if len(list(DataRefsTo(struct))) == 0:
        continue
    refTo = list(DataRefsTo(struct))[0]
    # info.superFuncName = GetFunctionName(refTo)
    info.superFuncName = get_func_name(refTo)
    # info.superFunc = LocByName(info.superFuncName)
    info.superFunc = get_name_ea_simple(info.superFuncName)

    AllGlobalBlockMap[func] = info

def funcIsGlobalBlockFunc(block_func):
    return block_func in AllGlobalBlockMap


def isPossibleStackBlockForFunc(block_func):
# def superFuncForStackBlock(block_func):

    if not isInText(block_func):
        return False

    # if GetFunctionAttr(block_func,FUNCATTR_START) != (block_func & ~ 1):
    if get_func_attr(block_func,FUNCATTR_START) != (block_func & ~ 1):
        return False

    #block addr cannot be called directly
    if len(list(CodeRefsTo(block_func, 0))) !=0 :
        # print '%x is not block because be call by %x' % (block_func ,list(CodeRefsTo(block_func, 0))[0])
        return False

    # ref to block should be in text section
    refsTo = list(DataRefsTo(block_func))
    for addr in refsTo:
        if not isInText(addr):
            # print '%x is not block because be ref from %x' % (block_func, addr)
            return False

    # block func should be ref in only 1 function
    # superFuncs = [GetFunctionAttr(x,FUNCATTR_START) for x in refsTo]
    superFuncs = [get_func_attr(x,FUNCATTR_START) for x in refsTo]
    superFuncs = list (set (superFuncs))
    if len(superFuncs) != 1:
        # print '%x is not block because be not ref from  1 function' % block_func
        return False

    return True

def superFuncForStackBlock(block_func):
    refsTo = list(DataRefsTo(block_func))
    # superFuncs = [GetFunctionAttr(x,FUNCATTR_START) for x in refsTo]
    superFuncs = [get_func_attr(x,FUNCATTR_START) for x in refsTo]
    superFuncs = list (set (superFuncs))
    if len(superFuncs) != 1:
        return None
    super_func_addr = superFuncs[0]
    if IS_MAC:
        return super_func_addr
    else:
        # return super_func_addr | GetReg(super_func_addr, "T") # thumb
        return super_func_addr | get_sreg(super_func_addr, "T") # thumb


def superFuncForBlockFunc(block_func):
    if funcIsGlobalBlockFunc(block_func):
        return AllGlobalBlockMap[block_func].superFunc

    superStackFunc = superFuncForStackBlock(block_func)
    return superStackFunc # maybe None


resultDict = {}

maxRecursionDepth = 80
# maxRecursionDepth = 200
# maxRecursionDepth = 400

gRecursionFuncDict = {}
gExceededMaxRecursionList = []

def findBlockName(block_func):
    # print("findBlockName: %X" % block_func)

    retFuncName = ""

    if block_func in gExceededMaxRecursionList:
        return retFuncName

    # print("into func: gRecursionFuncDict=%s" % gRecursionFuncDict)

    if block_func not in gRecursionFuncDict.keys():
        gRecursionFuncDict[block_func] = 1
        # print("after init: gRecursionFuncDict=%s" % gRecursionFuncDict)
    else:
        curRecursionDepth = gRecursionFuncDict[block_func]
        # print("curRecursionDepth=%s" % gRecursionFuncDict)
        if curRecursionDepth >= maxRecursionDepth:
            gRecursionFuncDict.pop(block_func, None)
            gExceededMaxRecursionList.append(block_func)
            return retFuncName
        else:
            gRecursionFuncDict[block_func] = curRecursionDepth + 1
            # print("after update: gRecursionFuncDict=%s" % gRecursionFuncDict)

    # retFuncName = GetFunctionName(block_func)
    retFuncName = get_func_name(block_func)
    isNameNotEmpty = len(retFuncName) != 0
    isObjcFuncName = False
    if isNameNotEmpty:
        isObjcFuncName = retFuncName[0] in ('-', '+')
    isNameValid = isNameNotEmpty and isObjcFuncName
    if not isNameValid:
        # maybe nested block
        superBlockFuncAddr = superFuncForBlockFunc(block_func)
        if superBlockFuncAddr == None:
            # return ""
            retFuncName = ""
        else:
            if not IS_MAC:
                # superBlockFuncAddr = superBlockFuncAddr | GetReg(superBlockFuncAddr, "T") # thumb
                superBlockFuncAddr = superBlockFuncAddr | get_sreg(superBlockFuncAddr, "T") # thumb
                
            superBlockName = findBlockName(superBlockFuncAddr)
            if len(superBlockName) == 0:
                # return ""
                retFuncName = ""
            else:
                # return superBlockName + "_block"
                retFuncName = superBlockName + "_block"

    # del gRecursionFuncDict[block_func]
    gRecursionFuncDict.pop(block_func, None)
    # print("before return: gRecursionFuncDict=%s" % gRecursionFuncDict)

    print("%s -> %s" % (block_func, retFuncName))
    return retFuncName

#find all possible Stack Block 
allPossibleStackBlockFunc = []
allRefToBlock=[]
if IS32BIT:
    # allRefToBlock = list(DataRefsTo(LocByName("__NSConcreteStackBlock")))
    allRefToBlock = list(DataRefsTo(get_name_ea_simple("__NSConcreteStackBlock")))
else:
    # allRefToBlock = list(DataRefsTo(LocByName("__NSConcreteStackBlock_ptr")))
    allRefToBlock = list(DataRefsTo(get_name_ea_simple("__NSConcreteStackBlock_ptr")))
    allRefToBlock.sort()

    '''
    2 ref (@PAGE , @PAGEOFF) to __NSConcreteStackBlock_ptr , 
    but once actual
    filter the list
    __text:0000000102D9979C                 ADRP            X8, #__NSConcreteStackBlock_ptr@PAGE
    __text:0000000102D997A0                 LDR             X8, [X8,#__NSConcreteStackBlock_ptr@PAGEOFF]
    '''
    tmp_array = allRefToBlock[:1]
    for i in range(1, len(allRefToBlock)):
        if allRefToBlock[i] - allRefToBlock[i - 1] <= 8:
            pass
        else:
            tmp_array.append(allRefToBlock[i])
    allRefToBlock = tmp_array

# allRefToBlock = filter(lambda x:isInText(x), allRefToBlock)
# allRefToBlock = list(filter(lambda x:isInText(x), allRefToBlock))
allRefToBlock = [x for x in allRefToBlock if isInText(x)]

for addr in allRefToBlock:
    LineNumAround = 30 #Around 30 arm instruction
    # scan_addr_min= max (addr - LineNumAround * 4, GetFunctionAttr(addr,FUNCATTR_START))
    scan_addr_min= max (addr - LineNumAround * 4, get_func_attr(addr,FUNCATTR_START))
    # scan_addr_max= min (addr + LineNumAround * 4, GetFunctionAttr(addr,FUNCATTR_END))
    scan_addr_max= min (addr + LineNumAround * 4, get_func_attr(addr,FUNCATTR_END))
    for scan_addr in range(scan_addr_min, scan_addr_max):
        allPossibleStackBlockFunc += list(DataRefsFrom(scan_addr)) # all function pointer used around __NSConcreteStackBlock

allPossibleStackBlockFunc = list (set (allPossibleStackBlockFunc))

# allPossibleStackBlockFunc = filter(lambda x:isPossibleStackBlockForFunc(x) , allPossibleStackBlockFunc )
# allPossibleStackBlockFunc = list(filter(lambda x:isPossibleStackBlockForFunc(x) , allPossibleStackBlockFunc ))
allPossibleStackBlockFunc = [x for x in allPossibleStackBlockFunc if isPossibleStackBlockForFunc(x)]

#process all Global Block 
for block_func in AllGlobalBlockMap:
    block_name = findBlockName(block_func)
    resultDict[block_func] =  block_name

for block_func in allPossibleStackBlockFunc:
    block_name = findBlockName(block_func)
    resultDict[block_func] = block_name

list_output = []
error_num = 0
for addr in resultDict:
    name = resultDict[addr]
    if len(name) == 0 or name[0] not in ('-', '+'):
        error_num += 1
        continue

    list_output += [{"address":("0x%X" % addr), "name":name}]

encodeJson = json.dumps(list_output, indent=1)
f = open(outputFullFilename, "w")
f.write(encodeJson)
f.close()

print("Result file: %s" % outputFullFilename)

# print 'restore block num %d ' % len(list_output)
# print 'origin  block num: %d(GlobalBlock: %d, StackBlock: %d)' % (len(allRefToBlock) + len(AllGlobalBlockMap), len(AllGlobalBlockMap), len(allRefToBlock))
print('restore block num %d' % len(list_output))
print('origin  block num: %d (GlobalBlock: %d, StackBlock: %d)' % (len(allRefToBlock) + len(AllGlobalBlockMap), len(AllGlobalBlockMap), len(allRefToBlock)))
