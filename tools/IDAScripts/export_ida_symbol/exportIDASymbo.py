# Function: IDA script plugin, export (functions) symbol from IDA (for Mach-O format)
# Author: Crifan Li
# Update: 20231124

# import idc
# import sys
# print("Try debug IDA Python plugin script in VSCode")
# print(sys.executable)
# idcHere = idc.here()
# print("idcHere=%s" % idcHere)
# idcHereHex = hex(idcHere)
# print("idcHereHex=%s" % idcHereHex)

import idautils
import idc
# from idaapi import PluginForm
import ida_nalt
import ida_segment
import operator
import csv
import sys
import json

import os
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
import time
import codecs

################################################################################
# Config & Settings
################################################################################

isVerbose = False
# isVerbose = True

isExportToFile = True
# isExportToFile = False

################################################################################
# Util Function
################################################################################

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

def saveJsonToFile(fullFilename, jsonValue, indent=2, fileEncoding="utf-8"):
    """
        save json dict into file
        for non-ascii string, output encoded string, without \\u xxxx
    """
    with codecs.open(fullFilename, 'w', encoding=fileEncoding) as jsonFp:
        json.dump(jsonValue, jsonFp, indent=indent, ensure_ascii=False)
        # logging.debug("Complete save json %s", fullFilename)

#-------------------- IDA Utils --------------------

# get IDA info
def getIdaInfo():
  info = idaapi.get_inf_structure()
  print("info=%s" % info)
  return info

# print IDA info
def printIdaInfo(info):
  version = info.version
  print("version=%s" % version)
  is64Bit = info.is_64bit()
  print("is64Bit=%s" % is64Bit)
  procName = info.procname
  print("procName=%s" % procName)
  entryPoint = info.start_ea
  print("entryPoint=0x%X" % entryPoint)
  baseAddr = info.baseaddr
  print("baseAddr=0x%X" % baseAddr)

# print all imports lib and functions inside lib
def printAllImports():
  nimps = ida_nalt.get_import_module_qty()
  print("Found %d import(s)..." % nimps)
  for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
      print("Failed to get import module name for [%d] %s" % (i, name))
      name = "<unnamed>"
    else:
      print("[%d] %s" % (i, name))

    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    ida_nalt.enum_import_names(i, imp_cb)

# print segment info
# Note: is IDA segment == section
def printSegment(curSeg):
  segName = curSeg.name
  # print("type(segName)=%s" % type(segName))
  segSelector = curSeg.sel
  segStartAddr = curSeg.start_ea
  segEndAddr = curSeg.end_ea
  print("Segment: [0x%X-0x%X] name=%s, selector=%s : seg=%s" % (segStartAddr, segEndAddr, segName, segSelector, curSeg))

# get segment list
def getSegmentList():
  segList = []
  segNum = ida_segment.get_segm_qty()
  for segIdx in range(segNum):
    curSeg = ida_segment.getnseg(segIdx)
    # print("curSeg=%s" % curSeg)
    segList.append(curSeg)
    # printSegment(curSeg)
  return segList

# test get segment info
def testGetSegment():
  # textSeg = ida_segment.get_segm_by_name("__TEXT")
  # dataSeg = ida_segment.get_segm_by_name("__DATA")

  # getSegmentList()

  # NAME___TEXT = "21"
  # NAME___TEXT = 21
  # NAME___TEXT = "__TEXT,__text"
  # NAME___TEXT = "__TEXT:__text"
  # NAME___TEXT = ".text"

  """
    __TEXT,__text
    __TEXT,__stubs
    __TEXT,__stub_helper
    __TEXT,__objc_stubs
    __TEXT,__const
    __TEXT,__objc_methname
    __TEXT,__cstring
    __TEXT,__swift5_typeref
    __TEXT,__swift5_protos
    __TEXT,__swift5_proto
    __TEXT,__swift5_types
    __TEXT,__objc_classname
    __TEXT,__objc_methtype
    __TEXT,__gcc_except_tab
    __TEXT,__ustring
    __TEXT,__unwind_info
    __TEXT,__eh_frame
    __TEXT,__oslogstring

    __DATA,__got
    __DATA,__la_symbol_ptr
    __DATA,__mod_init_func
    __DATA,__const
    __DATA,__cfstring
    __DATA,__objc_classlist
    __DATA,__objc_catlist
    __DATA,__objc_protolist
    __DATA,__objc_imageinfo
    __DATA,__objc_const
    __DATA,__objc_selrefs
    __DATA,__objc_protorefs
    __DATA,__objc_classrefs
    __DATA,__objc_superrefs
    __DATA,__objc_ivar
    __DATA,__objc_data
    __DATA,__data
    __DATA,__objc_stublist
    __DATA,__swift_hooks
    __DATA,__swift51_hooks
    __DATA,__s_async_hook
    __DATA,__swift56_hooks
    __DATA,__thread_vars
    __DATA,__thread_bss
    __DATA,__bss
    __DATA,__common
  """

  # __TEXT,__text
  NAME___text = "__text"
  textSeg = ida_segment.get_segm_by_name(NAME___text)
  print("textSeg: %s -> %s" % (NAME___text, textSeg))
  printSegment(textSeg)

  # __TEXT,__objc_methname
  NAME___objc_methname = "__objc_methname"
  objcMethNameSeg = ida_segment.get_segm_by_name(NAME___objc_methname)
  print("objcMethNameSeg: %s -> %s" % (NAME___objc_methname, objcMethNameSeg))
  printSegment(objcMethNameSeg)

  # __DATA,__got
  NAME___got = "__got"
  gotSeg = ida_segment.get_segm_by_name(NAME___got)
  print("gotSeg: %s -> %s" % (NAME___got, gotSeg))
  printSegment(gotSeg)

  # __DATA,__data
  # NAME___DATA = "22"
  # NAME___DATA = 22
  NAME___DATA = "__data"
  dataSeg = ida_segment.get_segm_by_name(NAME___DATA)
  print("dataSeg: %s -> %s" % (NAME___DATA, dataSeg))
  printSegment(dataSeg)

  # exist two one: __TEXT,__const / __DATA,__const
  NAME___const = "__const"
  constSeg = ida_segment.get_segm_by_name(NAME___const)
  print("constSeg: %s -> %s" % (NAME___const, constSeg))
  printSegment(constSeg)


################################################################################
# Main
################################################################################

print("%s Prepare %s" % ("="*40, "="*40))

imageBase = idaapi.get_imagebase()
# imageBaseStr = "ImageBase0x%X" % imageBase
print("Image Base: 0x%X = %d" % (imageBase, imageBase))

idaVersion = idaapi.IDA_SDK_VERSION
print("IDA Version: %s" % idaVersion)

idaRootFilename = get_root_filename()
print("IDA root filename: %s" % idaRootFilename)

inputFileFullPath = ida_nalt.get_input_file_path()
# print("inputFileFullPath=%s" % inputFileFullPath)
outputFolder = os.path.dirname(inputFileFullPath)
# print("outputFolder=%s" % outputFolder)

# changeLogStr = imageBaseStr
# changeLogStr = "omitImportFunc"
changeLogStr = "FunctionsNames"

# outputFilename = "IDAFunctionsSymbol"
outputFilename = "IDASymbols"
# outputFullFilename = "%s_%s_%s.json" % (getFilenameNoPointSuffix(__file__), outputFilename, getCurDatetimeStr())
# outputFullFilename = "%s_%s_%s.json" % (idaRootFilename, outputFilename, getCurDatetimeStr())
# outputFullFilename = "%s_%s_%s_%s.json" % (idaRootFilename, outputFilename, imageBaseStr, getCurDatetimeStr())
outputFullFilename = "%s_%s_%s_%s.json" % (idaRootFilename, outputFilename, changeLogStr, getCurDatetimeStr())
print("outputFullFilename=%s" % outputFullFilename)

lastDataSegmentSectionName = "__common"
commonSeg = ida_segment.get_segm_by_name(lastDataSegmentSectionName)
print("__common segment: %s -> %s" % (lastDataSegmentSectionName, commonSeg))
printSegment(commonSeg)
lastValidEndAddr = commonSeg.end_ea
print("End valid Functions Symbol address: 0x%X" % lastValidEndAddr)

functionsSymbolDictList = []

functionIterator = idautils.Functions()
# print("type(functionList)=%s" % type(functionList))

print("%s Exporting IDA Symbols %s" % ("="*40, "="*40))

print("%s Functions Symbols %s" % ("-"*30, "-"*30))

functionAddrList = []
for curFuncAddr in functionIterator:
  functionAddrList.append(curFuncAddr)
totalFunctionsCount = len(functionAddrList)
print("totalFunctionsCount=%s" % totalFunctionsCount)

# # for debug
# impFunNum = 0

validFunctionsSymbolCount = 0
invalidFunctionsSymbolCount = 0

eliteLogPerNum = int(totalFunctionsCount / 100)
print("eliteLogPerNum=%s" % eliteLogPerNum)

curNum = 0
for curFunc in functionAddrList:
  curNum += 1
  # print("curFunc=%s" % curFunc)
  # curFuncAddrStr = hex(curFunc)
  curFuncAddrStr = "0x%X" % curFunc
  curFuncName = idc.get_func_name(curFunc)
  # print("curFuncName=%s" % curFuncName)

  curFuncAttr_end = idc.get_func_attr(curFunc, attr=FUNCATTR_END)

  isValid = not (curFuncAttr_end > lastValidEndAddr)

  if isValid:
    validFunctionsSymbolCount += 1

    isLogCurrent = False
    if isVerbose:
       isLogCurrent = True
    else:
      if (curNum % eliteLogPerNum == 0):
       isLogCurrent = True

    curFuncAttr_start = idc.get_func_attr(curFunc, attr=FUNCATTR_START)
    curFuncSize = curFuncAttr_end - curFuncAttr_start
    curFuncSizeStr = "0x%X" % curFuncSize

    curFuncAttr_flags = idc.get_func_flags(curFunc)
    curFuncFlagsStr = "0x%X" % curFuncAttr_flags

    # curFuncComments = idc.get_func_cmt(curFunc, repeatable=0)
    # curFuncAttr_owner = idc.get_func_attr(curFunc, attr=FUNCATTR_OWNER)

    # # for debug
    # if curFuncName.startswith("__imp"):
    #   impFunNum += 1

    # if impFunNum >= 3:
    #   llllll

    if isLogCurrent:
      # print("[%d] addr=%s, name=%s, size=%s, flags=%s, owner=0x%X" % (toPrintNum, curFuncAddrStr, curFuncName, curFuncSizeStr, curFuncFlagsStr, curFuncAttr_owner))
      print("[%d/%d] addr=%s, name=%s, size=%s" % (curNum, totalFunctionsCount, curFuncAddrStr, curFuncName, curFuncSizeStr))

    curSymbolDict = {
      "name": curFuncName,
      "address": curFuncAddrStr,
      "size": curFuncSizeStr,
    }
    functionsSymbolDictList.append(curSymbolDict)
  else:
    invalidFunctionsSymbolCount += 1

validFunctionsSymbolCount = len(functionsSymbolDictList)

print("%s Names Symbols %s" % ("-"*30, "-"*30))

# nameTupleList = []
# nameNameList = []
# nameAddrList = []
# nameTupleIterator = idautils.Names()
# for nameTuple in nameTupleIterator:
#   # print("nameTuple=%s" % (nameTuple))
#   nameName, nameAddr = nameTuple
#   nameNameList.append(nameName)
#   nameAddrList.append(nameAddr)
#   nameTupleList.append(nameTuple)
# nameNum = len(nameTupleList)
# print("nameNum=%s" % nameNum)

# # isAllFuncSymInNames = True
# funcNameAndAddrBothInNamesDict = {}
# funcNameNotInNamesList = []
# funcAddrNotInNamesList = []
# funcNameAndAddrBothNotInNamesDict = {}
# for funcSymNum, eachFuncSymDict in enumerate(functionsSymbolDictList, start=1):
#   funcName = eachFuncSymDict["name"]
#   funcAddrStr = eachFuncSymDict["address"]
#   funcAddr = int(funcAddrStr, base=16)
#   isFuncNameInNames = funcName in nameNameList
#   isFuncAddrInNames = funcAddr in nameAddrList
#   curInfoStr = ""
#   if (isFuncNameInNames==False) and (isFuncAddrInNames==False):
#     funcNameAndAddrBothNotInNamesDict[funcName] = funcAddr
#     curInfoStr = "both not in Names: [0x0%X] %s" % (funcAddr, funcName)
#   elif (isFuncNameInNames == False):
#     funcNameNotInNamesList.append(funcName)
#     curInfoStr = "name not in Names: %s" % funcName
#   elif (isFuncAddrInNames == False):
#     funcAddrNotInNamesList.append(funcAddr)
#     curInfoStr = "address not in Names: [0x%X]" % funcAddr
#   else:
#     funcNameAndAddrBothInNamesDict[funcName] = funcAddr
#     curInfoStr = "both in Names: [0x0%X] %s" % (funcAddr, funcName)
#   print("[%d/%d] %s" % (funcSymNum, validFunctionsSymbolCount, curInfoStr))

#   # isFuncInNames = isFuncNameInNames and isFuncAddrInNames
#   # if not isFuncInNames:
#   #   isAllFuncSymInNames = False
#   #   break
# # print("isAllFuncSymInNames=%s" % isAllFuncSymInNames)

# print("Total valid Functions symbol count: %d" % validFunctionsSymbolCount)
# print("  both name and address in Names count: %d" % len(funcNameAndAddrBothInNamesDict.keys()))
# print("  function name not in Names count: %d" % len(funcNameNotInNamesList))
# print("  function address not in Names count: %d" % len(funcAddrNotInNamesList))
# print("  both name and address not in Names count: %d" % len(funcNameAndAddrBothNotInNamesDict.keys()))

totalNamesCount = 0
emptyNameCount = 0
namesSymbolDictList = []
nameTupleIterator = idautils.Names()
for (nameAddr, nameName) in nameTupleIterator:
  totalNamesCount += 1
  if nameName:
    nameAddrStr = "0x%X" % nameAddr
    curNamesSymbolDict = {
      "name": nameName,
      "address": nameAddrStr,
    }
    namesSymbolDictList.append(curNamesSymbolDict)
  else:
    emptyNameCount += 1
    if isVerbose:
      print("Omit: empty name for [0x%X]" % nameAddr)

namesSymbolCount = len(namesSymbolDictList)
print("namesSymbolCount=%s" % namesSymbolCount)

print("%s Merging Symbols %s" % ("-"*30, "-"*30))

idaSymbolDictList = functionsSymbolDictList + namesSymbolDictList
totalIdaSymbolCount = len(idaSymbolDictList)
print("totalIdaSymbolCount=%s" % totalIdaSymbolCount)

print("%s Summary Info %s" % ("="*40, "="*40))

print("Total IDA symbols count: %d" % totalIdaSymbolCount)
print("  Functions symbol count: %d" % validFunctionsSymbolCount)
print("    Total Functions count: %d" % totalFunctionsCount)
print("    Invalid Functions symbol count: %d" % invalidFunctionsSymbolCount)
print("  Names symbol count: %d" % namesSymbolCount)
print("    Total Names count: %d" % totalNamesCount)
print("    Empty Names count: %d" % emptyNameCount)

if isExportToFile:
  print("Exporting %d IDA symbol to" % totalIdaSymbolCount)
  print("  folder: %s" % outputFolder)
  print("  file: %s" % outputFullFilename)
  saveJsonToFile(outputFullFilename, idaSymbolDictList)
  print("Export complete")
