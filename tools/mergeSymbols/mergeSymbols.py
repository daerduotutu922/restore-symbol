# Function: Merge symbols from exported from IDA (functions), restore-symbol restored, scanned Objc block
# Author: Crifan Li
# Update: 20231113

import os
import json
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
import codecs
import copy

# import cxxfilt

# symNameList = [
#   "N3foo12BarExceptionE",
#   "_ZN7mangled3fooEd",
#   "_ZNSt22condition_variable_anyD2Ev",

#   # "s6FindMy15FMTaskSchedulerC6sharedACvau",
#   # "_s6FindMy15FMTaskSchedulerC6sharedACvau",
  
#   "_$s6FindMy15FMTaskSchedulerC6sharedACvau",
#   "_$sSo8NSBundleC15WAContactPickerE07contactC15ResourcesBundleABSgvgZ",
#   "_$sSo8NSBundleC15WAContactPickerE07contactC15ResourcesBundleABSgvsZ",
#   "_$sSo8NSBundleC15WAContactPickerE07contactC15ResourcesBundleABSgvMZ",
# ]
# for symName in symNameList:
#   # demangledSymName = cxxfilt.demangle(symName, external_only=False)
#   demangledSymName = cxxfilt.demangle(symName)
#   print("%s -> %s" % (symName, demangledSymName))

# print()

################################################################################
# Config & Settings & Const
################################################################################

curAppName = "WhatsApp"
# idaFunctionsSymbolFileName = "WhatsApp_IDAFunctionsSymbol_20231112_174504.json"
idaFunctionsSymbolFileName = "WhatsApp_IDAFunctionsSymbol_ImageBase0x100000000_20231114_114528.json"
restoreSymbolObjcSymbolFileName = "WhatsApp_objcNoDupSymbols_20231105.json"
idaBlockSymbolFileName = "WhatsApp_block_symbol_20231027_114208.json"

# curAppName = "SharedModules"
# idaFunctionsSymbolFileName = "SharedModules_IDAFunctionsSymbol_20231112_175710.json"
# restoreSymbolObjcSymbolFileName = "SharedModules_objcNoDupSymbols_20231108.json"
# idaBlockSymbolFileName = "SharedModules_block_symbol_20231027_153048.json"

################################################################################
# Global Variable
################################################################################

curFilePath = os.path.abspath(__file__)
curFolder = os.path.dirname(curFilePath)
print("curFilePath=%s, curFolder=%s" % (curFilePath, curFolder))

inputFolderName = os.path.join("input", curAppName)
idaFunctionsSymbolFile = os.path.join(curFolder, inputFolderName, idaFunctionsSymbolFileName)
restoreSymbolObjcSymbolFile = os.path.join(curFolder, inputFolderName, restoreSymbolObjcSymbolFileName)
idaBlockSymbolFile = os.path.join(curFolder, inputFolderName, idaBlockSymbolFileName)

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


def loadJsonFromFile(fullFilename, fileEncoding="utf-8"):
  """load and parse json dict from file"""
  with codecs.open(fullFilename, 'r', encoding=fileEncoding) as jsonFp:
    jsonDict = json.load(jsonFp)
    # logging.debug("Complete load json from %s", fullFilename)
    return jsonDict

################################################################################
# Main
################################################################################

outputBaseFilename = "mergedSymbols"
outputFilename = "%s_%s_%s.json" % (curAppName, outputBaseFilename, getCurDatetimeStr())
# print("outputFilename=%s" % outputFilename)
outputFullFilename = os.path.join(curFolder, "output", outputFilename)
# print("outputFullFilename=%s" % outputFullFilename)

print("1. Load IDA exported symbols: %s" % idaFunctionsSymbolFileName)
idaFunctionsSymbolList = loadJsonFromFile(idaFunctionsSymbolFile)
print("  len(idaFunctionsSymbolList)=%s" % len(idaFunctionsSymbolList))

print("  Parsing IDA symbols")

idaFunctionsSymbolDict = {}
for eachSymbolDict in idaFunctionsSymbolList:
  symName = eachSymbolDict["name"]
  symAddStr = eachSymbolDict["address"]
  # to support hex, both capital and lowercase
  symAddInt = int(symAddStr, base=16)
  symSizeStr = eachSymbolDict["size"]
  symSizeInt = int(symSizeStr, base=16)

  idaFunctionsSymbolDict[symName] = {
    "address": symAddInt,
    "size": symSizeInt,
  }

idaFunctionsSymbolDictKeys = idaFunctionsSymbolDict.keys()
print("  len(idaFunctionsSymbolDictKeys)=%s" % len(idaFunctionsSymbolDictKeys))

mergedSymbolDict = copy.deepcopy(idaFunctionsSymbolDict)
mergedSymbolDictKeys = mergedSymbolDict.keys()
print("  len(mergedSymbolDictKeys)=%s" % len(mergedSymbolDictKeys))

print("2. Merge restore-symbol restored Objc symbols: %s" % restoreSymbolObjcSymbolFileName)
# rs = restore-symbol
rsObjcSymbolList = loadJsonFromFile(restoreSymbolObjcSymbolFile)
rsObjcSymbolNum = len(rsObjcSymbolList)
print("  rsObjcSymbolNum=%s" % rsObjcSymbolNum)

SymbolNum_RsInIda = 0
SymbolNum_RsInIda_AddrSame = 0
SymbolNum_RsInIda_AddrNotSame = 0
SymbolNum_RsNotInIda = 0
for curRsObjSymDict in rsObjcSymbolList:
  rsSymName = curRsObjSymDict["name"]
  rsSymAddrStr = curRsObjSymDict["address"]
  rsSymAddr = int(rsSymAddrStr, base=16)
  rsSymTypeStr = curRsObjSymDict["type"]
  rsSymType = int(rsSymTypeStr, base=16)

  # for debug
  if not rsSymType:
    print("  Abnormal: restore-symbol symbol no type for: %s" % curRsObjSymDict)

  if rsSymName in mergedSymbolDictKeys:
    SymbolNum_RsInIda += 1
    idaSymDict = mergedSymbolDict[rsSymName]
    idaSymAddr = idaSymDict["address"]
    if (rsSymAddr == idaSymAddr): # if not same -> use(keep) IDA symbol
      SymbolNum_RsInIda_AddrSame += 1
      idaSymDict["type"] = rsSymType
    else:
      SymbolNum_RsInIda_AddrNotSame += 1
  else:
    SymbolNum_RsNotInIda += 1
    mergedSymbolDict[rsSymName] = {
      "address": rsSymAddr,
      "type": rsSymType,
    }

print("  Total restored symbol number: %s" % rsObjcSymbolNum)
print("   in IDA: %s" % SymbolNum_RsInIda)
print("     in IDA, same address: %s" % SymbolNum_RsInIda_AddrSame)
print("     in IDA, not same address: %s" % SymbolNum_RsInIda_AddrNotSame)
print("   not in IDA: %s" % SymbolNum_RsNotInIda)

print("3. Merge IDA scanned block symbols: %s" % idaBlockSymbolFileName)
idaBlockSymbolList = loadJsonFromFile(idaBlockSymbolFile)
idaBlockSymbolNum = len(idaBlockSymbolList)
print("  idaBlockSymbolNum=%s" % idaBlockSymbolNum)

# Note: above symbol list have changed, so need updated
mergedSymbolDictKeys = mergedSymbolDict.keys()

SymbolNum_BlockInMerged = 0
SymbolNum_BlockInMerged_AddrSame = 0
SymbolNum_BlockInMerged_AddrNotSame = 0
SymbolNum_BlockNotInMerged = 0
for blockSymDict in idaBlockSymbolList:
  blockSymName = blockSymDict["name"]
  blockSymAddrStr = blockSymDict["address"]
  blockSymAddr = int(blockSymAddrStr, base=16)

  if blockSymName in mergedSymbolDictKeys:
    SymbolNum_BlockInMerged += 1
    mergedSymDict = mergedSymbolDict[blockSymName]
    mergedSymAddr = mergedSymDict["address"]
    if (blockSymAddr == mergedSymAddr): # if not same -> use(keep) merged symbol
      SymbolNum_BlockInMerged_AddrSame += 1
    else:
      SymbolNum_BlockInMerged_AddrNotSame += 1
  else:
    SymbolNum_BlockNotInMerged += 1
    mergedSymbolDict[blockSymName] = {
      "address": blockSymAddr,
    }

print("  Total block symbol number: %s" % idaBlockSymbolNum)
print("   in merged: %s" % SymbolNum_BlockInMerged)
print("     in merged, same address: %s" % SymbolNum_BlockInMerged_AddrSame)
print("     in merged, not same address: %s" % SymbolNum_BlockInMerged_AddrNotSame)
print("   not in merged: %s" % SymbolNum_BlockNotInMerged)

print("4. Output final merged symbols : %s" % outputFilename)
outputSymbolList = []
for symName, symDict in mergedSymbolDict.items():
  outputSymAddr = symDict["address"]
  outputSymAddrStr = "0x%X" % outputSymAddr
  outputSymDict = {
    "name": symName,
    "address": outputSymAddrStr,
  }

  if "type" in symDict:
    outputSymType = symDict["type"]
    if outputSymType != None:
      outputSymTypeStr = "0x%X" % outputSymType
      outputSymDict["type"] = outputSymTypeStr
    else:
      # for debug
      print("Abnormal: type is none for %s,%s" % (symName, symDict))

  if "size" in symDict:
    outputSymSize = symDict["size"]
    if outputSymSize != None:
      outputSymSizeStr = "0x%X" % outputSymSize
      outputSymDict["size"] = outputSymSizeStr
    else:
      # for debug
      print("Abnormal: size is none for %s,%s" % (symName, symDict))

  outputSymbolList.append(outputSymDict)

mergedSymbolNum = len(outputSymbolList)
print("  Exporting %d symbols to file %s" % (mergedSymbolNum, outputFilename))
saveJsonToFile(outputFullFilename, outputSymbolList)
print("  Exported final merged symbol file %s" % outputFullFilename)

print("")
