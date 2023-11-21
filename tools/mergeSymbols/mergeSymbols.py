# Function: Merge symbols from exported from IDA (functions), restore-symbol restored, scanned Objc block
# Author: Crifan Li
# Update: 20231121

import os
import json
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
import codecs
import copy
import argparse

################################################################################
# Config & Settings & Const
################################################################################

# appName = "WhatsApp"
# # idaSymbolFile = "WhatsApp_IDAFunctionsSymbol_20231112_174504.json"
# # idaSymbolFile = "WhatsApp_IDAFunctionsSymbol_ImageBase0x100000000_20231114_114528.json"
# # idaSymbolFile = "WhatsApp_IDAFunctionsSymbol_omitImportFunc_20231115_115215.json"
# idaSymbolFile = "WhatsApp_IDAFunctionsSymbol_omitImportFunc_20231117_222347.json"
# objcSymbolFile = "WhatsApp_objcNoDupSymbols_20231105.json"
# # blockSymbolFile = "WhatsApp_block_symbol_20231027_114208.json"
# blockSymbolFile = "WhatsApp_blockSymbolsRenamed_20231117_222445.json"

# appName = "SharedModules"
# # idaSymbolFile = "SharedModules_IDAFunctionsSymbol_20231112_175710.json"
# # idaSymbolFile = "SharedModules_IDAFunctionsSymbol_omitImportFunc_20231115_220343.json"
# # idaSymbolFile = "SharedModules_IDAFunctionsSymbol_omitImportFunc_20231117_224041.json"
# idaSymbolFile = "SharedModules_IDASymbols_FunctionsNames_20231119_165858.json"
# objcSymbolFile = "SharedModules_objcNoDupSymbols_20231108.json"
# # blockSymbolFile = "SharedModules_block_symbol_20231027_153048.json"
# # blockSymbolFile = "SharedModules_blockSymbolsRenamed_20231117_220017.json"
# blockSymbolFile = "SharedModules_blockSymbolsRenamed_20231117_224120.json"

mainDelimiter = "="*20

# enableMergeBlockSymbol = True
# enableMergeBlockSymbol = False

################################################################################
# Global Variable
################################################################################

curFilePath = os.path.abspath(__file__)
curFolder = os.path.dirname(curFilePath)
print("curFilePath=%s, curFolder=%s" % (curFilePath, curFolder))

# inputFolderName = os.path.join("input", appName)
# idaSymbolsFile = os.path.join(curFolder, inputFolderName, idaSymbolFile)
# objcSymbolFile = os.path.join(curFolder, inputFolderName, objcSymbolFile)
# blockSymbolFile = os.path.join(curFolder, inputFolderName, blockSymbolFile)

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

def mergeSymbols(
    appName=None,
    idaSymbolsFile=None,
    objcSymbolFile=None,
    blockSymbolFile=None,
    outputSymbolFile=None,
  ):
  print("Merge symbols for app: %s" % appName)

  mergedSymbolsDict = {}

  if idaSymbolsFile:
    print("%s Load IDA (Functons, Names) symbols %s" % (mainDelimiter, mainDelimiter))
    print("  IDA symbols file: %s" % idaSymbolFile)
    idaSymbolsList = loadJsonFromFile(idaSymbolsFile)
    print("  len(idaSymbolsList)=%s" % len(idaSymbolsList))

    print("  Parsing IDA symbols")

    idaSymbolsDict = {}
    for eachSymbolDict in idaSymbolsList:
      symName = eachSymbolDict["name"]
      symAddStr = eachSymbolDict["address"]
      # to support hex, both capital and lowercase
      symAddrInt = int(symAddStr, base=16)
      idaSymbolsDict[symName] = {
        "address": symAddrInt,
      }

      if "size" in eachSymbolDict:
        # for Names, no "size"
        symSizeStr = eachSymbolDict["size"]
        symSizeInt = int(symSizeStr, base=16)
        idaSymbolsDict[symName]["size"] = symSizeInt

    idaSymbolsDictKeys = idaSymbolsDict.keys()
    print("  Merged IDA symbol count %d" % len(idaSymbolsDictKeys))

    mergedSymbolsDict = copy.deepcopy(idaSymbolsDict)
    mergedSymbolsDictKeys = mergedSymbolsDict.keys()
    # print("  len(mergedSymbolsDictKeys)=%s" % len(mergedSymbolsDictKeys))

  if objcSymbolFile:
    print("%s Merge (restore-symbol restored) ObjC symbols %s" % (mainDelimiter, mainDelimiter))
    print("  Objc symbols file: %s" % objcSymbolFile)

    # rs = restore-symbol
    rsObjcSymbolList = loadJsonFromFile(objcSymbolFile)
    rsObjcSymbolNum = len(rsObjcSymbolList)
    print("  rsObjcSymbolNum=%s" % rsObjcSymbolNum)

    # # for debug
    # symbolDictList_objcNotInIda = []

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

      if rsSymName in mergedSymbolsDictKeys:
        SymbolNum_RsInIda += 1
        idaSymDict = mergedSymbolsDict[rsSymName]
        idaSymAddr = idaSymDict["address"]
        if (rsSymAddr == idaSymAddr): # if not same -> use(keep) IDA symbol
          SymbolNum_RsInIda_AddrSame += 1
          idaSymDict["type"] = rsSymType
        else:
          SymbolNum_RsInIda_AddrNotSame += 1
      else:
        SymbolNum_RsNotInIda += 1
        mergedSymbolsDict[rsSymName] = {
          "address": rsSymAddr,
          "type": rsSymType,
        }

        # # for debug
        # notInIdaSymbolDict = {
        #   "name": rsSymName,
        #   "address": "0x%X" % rsSymAddr,
        #   "type": "0x%X" % rsSymType,
        # }
        # symbolDictList_objcNotInIda.append(notInIdaSymbolDict)

    # # for debug
    # notInIdaObjcSymFilename = "%s_notInIdaObjcSymDictList_%s.json" % (appName, getCurDatetimeStr())
    # notInIdaObjcSymFullPath = os.path.join(curFolder, "output", notInIdaObjcSymFilename)
    # saveJsonToFile(notInIdaObjcSymFullPath, symbolDictList_objcNotInIda)

    # 回去看：name相同，地址不同的背后逻辑
    # 回去看：ObjC不在IDA中的符号，对应的地址，在IDA中，具体是什么（函数）？

    print("  Total restored symbol number: %s" % rsObjcSymbolNum)
    print("   in IDA: %s" % SymbolNum_RsInIda)
    print("     in IDA, same address: %s" % SymbolNum_RsInIda_AddrSame)
    print("     in IDA, not same address: %s" % SymbolNum_RsInIda_AddrNotSame)
    print("   not in IDA: %s" % SymbolNum_RsNotInIda)

  if blockSymbolFile:
    print("%s Merge IDA scanned objc block symbols %s" % (mainDelimiter , mainDelimiter))
    print("  Block symbols file: %s" % blockSymbolFile)

    idaBlockSymbolList = loadJsonFromFile(blockSymbolFile)
    idaBlockSymbolNum = len(idaBlockSymbolList)
    print("  idaBlockSymbolNum=%s" % idaBlockSymbolNum)

    # Note: above symbol list have changed, so need updated
    mergedSymbolsDictKeys = mergedSymbolsDict.keys()

    # generate new address: name dict, for later use
    mergedSymbolsAddrNameDict = {}
    for eachSymName, eachSymDict in mergedSymbolsDict.items():
      eachSymAddr = eachSymDict["address"]
      mergedSymbolsAddrNameDict[eachSymAddr] = eachSymName

    toRemoveSameAddrSymbolNameDict = []

    SymbolNum_BlockInMerged = 0
    SymbolNum_BlockInMerged_AddrSame = 0
    SymbolNum_BlockInMerged_AddrNotSame = 0
    SymbolNum_BlockNotInMerged = 0
    SymbolNum_BlockNotInMerged_SameAddr = 0
    for blockSymDict in idaBlockSymbolList:
      blockSymName = blockSymDict["name"]
      blockSymAddrStr = blockSymDict["address"]
      blockSymAddr = int(blockSymAddrStr, base=16)

      if blockSymName in mergedSymbolsDictKeys:
        SymbolNum_BlockInMerged += 1
        mergedSymDict = mergedSymbolsDict[blockSymName]
        mergedSymAddr = mergedSymDict["address"]
        if (blockSymAddr == mergedSymAddr):
          # if same address -> use/keep merged symbol
          SymbolNum_BlockInMerged_AddrSame += 1
        else:
          print("Same name=%s, but diff addr: merged=0x%X vs block=0x%X" % (blockSymName, mergedSymAddr, blockSymAddr))
          SymbolNum_BlockInMerged_AddrNotSame += 1
      else:
        SymbolNum_BlockNotInMerged += 1

        # if not same name -> use/keep block symbol
        # for eachSymbolName in mergedSymbolsDictKeys:
        #   echSymbolDict = mergedSymbolsDict[eachSymbolName]
        #   eachSymbolAddr = echSymbolDict["address"]
        #   if eachSymbolAddr == blockSymAddr:
        #     toRemoveSameAddrSymbolNameDict.append(eachSymbolName)

        # assume only one, if exist same address
        if blockSymAddr in mergedSymbolsAddrNameDict.keys():
          SymbolNum_BlockNotInMerged_SameAddr += 1
          sameAddrSymName = mergedSymbolsAddrNameDict[blockSymAddr]
          toRemoveSameAddrSymbolNameDict.append(sameAddrSymName)

        mergedSymbolsDict[blockSymName] = {
          "address": blockSymAddr,
        }

    for eachToRemoveSymName in toRemoveSameAddrSymbolNameDict:
      mergedSymbolsDict.pop(eachToRemoveSymName)

    print("  Total block symbol number: %s" % idaBlockSymbolNum)
    print("   in merged: %s" % SymbolNum_BlockInMerged)
    print("     in merged, same address: %s" % SymbolNum_BlockInMerged_AddrSame)
    print("     in merged, not same address: %s" % SymbolNum_BlockInMerged_AddrNotSame)
    print("   not in merged: %s" % SymbolNum_BlockNotInMerged)
    print("     same address(replaced name): %s" % SymbolNum_BlockNotInMerged_SameAddr)

  if outputSymbolFile:
    print("%s Output merged symbols %s" % (mainDelimiter , mainDelimiter))
    print("  Output file: %s" % outputSymbolFile)

    outputSymbolList = []
    for symName, symDict in mergedSymbolsDict.items():
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

    sortedOutputSymbolList = sorted(outputSymbolList, key=lambda eachDict: int(eachDict["address"], base=16))

    mergedSymbolNum = len(sortedOutputSymbolList)
    print("  Exporting %d symbols to file %s" % (mergedSymbolNum, outputSymbolFile))
    saveJsonToFile(outputSymbolFile, sortedOutputSymbolList)
    print("  Exported complete")


if __name__ == "__main__":
  newParser = argparse.ArgumentParser()
  newParser.add_argument("-a", "--app-name", type=str, dest="appName", default=None, help="app name")
  newParser.add_argument("-d", "--ida-symbol-file", type=str, dest="idaSymbolFile", default=None, help="IDA (Functions, Names) symbol file")
  newParser.add_argument("-c", "--objc-symbol-file", type=str, dest="objcSymbolFile", default=None, help="ObjC symbol file")
  newParser.add_argument("-b", "--block-symbol-file", type=str, dest="blockSymbolFile", default=None, help="Block symbol file")
  newParser.add_argument("-o", "--output-symbol-file", type=str, dest="outputSymbolFile", default=None, help="Output merged symbol file")
  args = newParser.parse_args()
  print("%s Parsing input arguments %s" % (mainDelimiter , mainDelimiter))
  print("args=%s" % args)

  # # for debug
  # args.appName="WhatsApp"
  # args.idaSymbolFile="input/WhatsApp/WhatsApp_IDASymbols_FunctionsNames_20231121_092816.json"
  # args.objcSymbolFile="input/WhatsApp/WhatsApp_objcNoDupSymbols_20231105.json"

  appName = args.appName
  print("appName=%s" % appName)
  idaSymbolFile = args.idaSymbolFile
  print("idaSymbolFile=%s" % idaSymbolFile)
  objcSymbolFile = args.objcSymbolFile
  print("objcSymbolFile=%s" % objcSymbolFile)
  blockSymbolFile = args.blockSymbolFile
  print("blockSymbolFile=%s" % blockSymbolFile)
  outputSymbolFile = args.outputSymbolFile
  print("outputSymbolFile=%s" % outputSymbolFile)
  if (not outputSymbolFile):
    outputSymbolFile = "%s_mergedSymbols_%s.json" % (appName, getCurDatetimeStr())
    print("outputSymbolFile=%s" % outputSymbolFile)

  mergeSymbols(
    appName=appName,
    idaSymbolsFile=idaSymbolFile,
    objcSymbolFile=objcSymbolFile,
    blockSymbolFile=blockSymbolFile,
    outputSymbolFile=outputSymbolFile
  )
