# Function: Merge symbols from exported from IDA (functions), restore-symbol restored, scanned Objc block
# Author: Crifan Li
# Update: 20231126

import os
import re
import json
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
import codecs
import copy
import argparse

################################################################################
# Config & Settings
################################################################################

isDebugRsIDADiff = True
# isDebugRsIDADiff = False

################################################################################
# Const
################################################################################

mainDelimiter = "="*20

################################################################################
# Global Variable
################################################################################

curFilePath = os.path.abspath(__file__)
curFolder = os.path.dirname(curFilePath)
print("curFilePath=%s, curFolder=%s" % (curFilePath, curFolder))

# for debug
gNoUse = 1

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


def diffNameCase_ObjcMetaClass(rsSymName, idaSymName):
  isCase_ObjcMetaClass = False
  # __OBJC_METACLASS_RO_$_WAAiStickerStrings == WAAiStickerStrings_$metaData
  rsObjcMetaclassRoMatch = re.search("__OBJC_METACLASS_RO_\$_(?P<rsClassName>\w+)", rsSymName)
  idaMetaDataMatch = re.search("(?P<idaClassName>\w+)_\$metaData", idaSymName)
  if rsObjcMetaclassRoMatch and idaMetaDataMatch:
    rsClassName = rsObjcMetaclassRoMatch.group("rsClassName")
    idaClassName = idaMetaDataMatch.group("idaClassName")
    if rsClassName and idaClassName:
      if rsClassName == idaClassName:
        isCase_ObjcMetaClass = True
  elif rsObjcMetaclassRoMatch:
    if rsSymName.endswith(idaSymName):
      # rsName=__OBJC_METACLASS_RO_$__TtC13WAFunStickers22AiStickersImageManager, idaName=AiStickersImageManager
      isCase_ObjcMetaClass = True
  return isCase_ObjcMetaClass

def diffNameCase_ObjcClass(rsSymName, idaSymName):
  isCase_ObjcClass = False
  # __OBJC_CLASS_RO_$_WADeviceInfo == WADeviceInfo_$classData
  rsObjcClassRoMatch = re.search("__OBJC_CLASS_RO_\$_(?P<rsClassName>\w+)", rsSymName)
  idaClassDataMatch = re.search("(?P<idaClassName>\w+)_\$classData", idaSymName)
  if rsObjcClassRoMatch and idaClassDataMatch:
    rsClassName = rsObjcClassRoMatch.group("rsClassName")
    idaClassName = idaClassDataMatch.group("idaClassName")
    if rsClassName and idaClassName:
      if rsClassName == idaClassName:
        isCase_ObjcClass = True
  elif rsObjcClassRoMatch:
    if rsSymName.endswith(idaSymName):
      # rsName=__OBJC_CLASS_RO_$__TtC13WAFunStickers22AiStickersImageManager, idaName=AiStickersImageManager
      isCase_ObjcClass = True
  return isCase_ObjcClass

def diffNameCase_ObjcClassProtocols(rsSymName, idaSymName):
  isCase_ObjcClassProtocols = False
  rsObjClassProtocolsMatch = re.search("__OBJC_CLASS_PROTOCOLS_\$_(?P<rsClassName>\w+)", rsSymName)
  # _TtC13WAFunStickers28AiStickersBloksActionHandler_$prots_0
  # _TtC13WAFunStickers28AiStickersBloksActionHandler_$prots
  idaProptsMatch = re.search("(?P<idaClassName>\w+)_\$prots_(\d+)?", idaSymName)
  if rsObjClassProtocolsMatch and idaProptsMatch:
    rsClassName = rsObjClassProtocolsMatch.group("rsClassName")
    idaClassName = idaProptsMatch.group("idaClassName")
    if rsClassName and idaClassName:
      if rsClassName == idaClassName:
        isCase_ObjcClassProtocols = True
  elif rsObjClassProtocolsMatch:
    if rsSymName.endswith(idaSymName):
      # rsName=__OBJC_CLASS_PROTOCOLS_$__TtC13WAFunStickers28AiStickersBloksActionHandler, idaName=AiStickersBloksActionHandler
      isCase_ObjcClassProtocols = True
  return isCase_ObjcClassProtocols

def diffNameCase_ObjcInstanceMethods(rsSymName, idaSymName):
  # __OBJC_$_INSTANCE_METHODS_WADeviceInfo == _OBJC_INSTANCE_METHODS_WADeviceInfo
  isCase_ObjcInstanceMethods = False
  rsObjcInstanceMethodsMatch = re.search("__OBJC_\$_INSTANCE_METHODS_(?P<rsClassName>\w+)", rsSymName)
  idaObjcInstanceMethodMatch = re.search("_OBJC_INSTANCE_METHODS_(?P<idaClassName>\w+)", idaSymName)
  if rsObjcInstanceMethodsMatch and idaObjcInstanceMethodMatch:
    rsClassName = rsObjcInstanceMethodsMatch.group("rsClassName")
    idaClassName = idaObjcInstanceMethodMatch.group("idaClassName")
    if rsClassName and idaClassName:
      if rsClassName == idaClassName:
        isCase_ObjcInstanceMethods = True
  return isCase_ObjcInstanceMethods

def diffNameCase_ObjcInstanceVariables(rsSymName, idaSymName):
  # __OBJC_$_INSTANCE_VARIABLES_WADeviceInfo == _OBJC_INSTANCE_VARIABLES_WADeviceInfo
  isCase_ObjcInstanceVariables = False
  rsObjcInstanceVariablesMatch = re.search("__OBJC_\$_INSTANCE_VARIABLES_(?P<rsClassName>\w+)", rsSymName)
  idaObjcInstanceVariablesMatch = re.search("_OBJC_INSTANCE_VARIABLES_(?P<idaClassName>\w+)", idaSymName)
  if rsObjcInstanceVariablesMatch and idaObjcInstanceVariablesMatch:
    rsClassName = rsObjcInstanceVariablesMatch.group("rsClassName")
    idaClassName = idaObjcInstanceVariablesMatch.group("idaClassName")
    if rsClassName and idaClassName:
      if rsClassName == idaClassName:
        isCase_ObjcInstanceVariables = True
  return isCase_ObjcInstanceVariables

def diffNameCase_ObjcPropertyList(rsSymName, idaSymName):
  # __OBJC_$_PROP_LIST_WADeviceInfo == WADeviceInfo_$properties
  # rsName=__OBJC_$_PROP_LIST_WAFunStickerUpSellView, idaName=WAFunStickerUpSellView_$properties
  isCase_ObjcPropertyList = False
  rsObjcPropListMatch = re.search("__OBJC_\$_PROP_LIST_(?P<rsClassName>\w+)", rsSymName)
  idaPropertiesMatch = re.search("(?P<idaClassName>\w+)_\$properties", idaSymName)
  if rsObjcPropListMatch and idaPropertiesMatch:
    rsClassName = rsObjcPropListMatch.group("rsClassName")
    idaClassName = idaPropertiesMatch.group("idaClassName")
    if rsClassName and idaClassName:
      if rsClassName == idaClassName:
        isCase_ObjcPropertyList = True
  return isCase_ObjcPropertyList

def diffNameCase_DemangledOrExtended(rsSymName, idaSymName):
  isCase_DemangledOrExtended = False
  # rsName=-[_TtC13WAFunStickersP33_7425D6185975D598F1BCFF05BD9A5C6317SearchBarLeftView .cxx_destruct], idaName=-[SearchBarLeftView .cxx_destruct]
  # rs: -[WAContactsStorage(MainApp) inNetworkContactsForJID:inContext:], IDA: -[WAContactsStorage inNetworkContactsForJID:inContext:]
  rsObjcFuncMatch = re.search("[\-\+]\[(?P<rsObjcClass>\w+)\((\w+)\) (?P<rsObjcFunc>\S+)\]", rsSymName)
  idaObjcFuncMatch = re.search("[\-\+]\[(?P<idaObjcClass>\w+) (?P<idaObjcFunc>\S+)\]", idaSymName)
  if rsObjcFuncMatch and idaObjcFuncMatch:
    rsObjcClass = rsObjcFuncMatch.group("rsObjcClass")
    rsObjcFunc = rsObjcFuncMatch.group("rsObjcFunc")
    idaObjcClass = idaObjcFuncMatch.group("idaObjcClass")
    idaObjcFunc = idaObjcFuncMatch.group("idaObjcFunc")
    # if (rsObjcFunc == idaObjcFunc) and rsObjcClass.endswith(idaObjcClass):
    if rsObjcFunc == idaObjcFunc:
      if rsObjcClass.endswith(idaObjcClass):
        isCase_DemangledOrExtended = True
      elif rsObjcClass == idaObjcClass:
        isCase_DemangledOrExtended = True
  return isCase_DemangledOrExtended

# check restore-symbol vs IDA symbol name, is known case or not
def isRsIdaKnownDiffNameCase(rsSymName, idaSymName):
  # Symbol Name: restore-symbol vs IDA
  isKnownCase = False

  if not isKnownCase:
    isKnownCase = diffNameCase_ObjcMetaClass(rsSymName, idaSymName)

  if not isKnownCase:
    isKnownCase = diffNameCase_ObjcClass(rsSymName, idaSymName)

  if not isKnownCase:
    isKnownCase = diffNameCase_ObjcClassProtocols(rsSymName, idaSymName)

  if not isKnownCase:
    isKnownCase = diffNameCase_ObjcInstanceMethods(rsSymName, idaSymName)

  if not isKnownCase:
    isKnownCase = diffNameCase_ObjcInstanceVariables(rsSymName, idaSymName)

  if not isKnownCase:
    isKnownCase = diffNameCase_ObjcPropertyList(rsSymName, idaSymName)

  if not isKnownCase:
    isKnownCase = diffNameCase_DemangledOrExtended(rsSymName, idaSymName)

  return isKnownCase


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
      if not symName:
        print("Invalid symbol: empty name for %s" % eachSymbolDict)
        continue

      symAddStr = eachSymbolDict["address"]
      # to support hex, both capital and lowercase
      symAddrInt = int(symAddStr, base=16)

      curSymValueDict = {
        "name": symName,
      }

      if "size" in eachSymbolDict:
        # for Names, no "size"
        symSizeStr = eachSymbolDict["size"]
        symSizeInt = int(symSizeStr, base=16)
        curSymValueDict["size"] = symSizeInt
      
      # for debug
      if symAddrInt in idaSymbolsDict:
        oldSymDict = idaSymbolsDict[symAddrInt]
        print("IDA Dup addr: old: %s <-> new: %s" % (oldSymDict, curSymValueDict))

      idaSymbolsDict[symAddrInt] = curSymValueDict

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

    if isDebugRsIDADiff:
      symbolDictList_objcNotInIda = []
      symbolDictList_rsIdaSameAddrNotSameName = []

    SymbolNum_RsInIda = 0
    SymbolNum_RsInIda_AddrSame = 0
    SymbolNum_RsInIda_AddrNotSame = 0
    SymbolNum_RsInIda_AddrNotSame_knownCase = 0
    SymbolNum_RsInIda_AddrNotSame_unknownCase = 0
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

      if rsSymAddr in mergedSymbolsDictKeys:
        SymbolNum_RsInIda += 1
        idaSymDict = mergedSymbolsDict[rsSymAddr]
        idaSymName = idaSymDict["name"]
        if (rsSymName == idaSymName):
          SymbolNum_RsInIda_AddrSame += 1
          # inline update dict
          idaSymDict["type"] = rsSymType
        else:
          SymbolNum_RsInIda_AddrNotSame += 1
          # Special case: address same, but name diff
          isKnownDiffNameCase = isRsIdaKnownDiffNameCase(rsSymName, idaSymName)
          if isKnownDiffNameCase:
            SymbolNum_RsInIda_AddrNotSame_knownCase += 1
            #   for known case, igore -> use IDA name
            # then update type
            idaSymDict["type"] = rsSymType
          else:
            SymbolNum_RsInIda_AddrNotSame_unknownCase += 1
            if isDebugRsIDADiff:
              # #   for other unknown case: need attention
              # print("[rs:IDA] same addr [0x%X] diff name: %s <-> %s" % (rsSymAddr, rsSymName, idaSymName))

              # save to list for furture research
              rsIdaSameAddrNotSameNameDict = {
                "address": rsSymAddrStr,
                "name": {
                  "rs": rsSymName,
                  "ida": idaSymName,
                }
              }
              symbolDictList_rsIdaSameAddrNotSameName.append(rsIdaSameAddrNotSameNameDict)
      else:
        SymbolNum_RsNotInIda += 1
        mergedSymbolsDict[rsSymAddr] = {
          "name": rsSymName,
          "type": rsSymType,
        }

        if isDebugRsIDADiff:
          notInIdaSymbolDict = {
            "name": rsSymName,
            "address": "0x%X" % rsSymAddr,
            "type": "0x%X" % rsSymType,
          }
          symbolDictList_objcNotInIda.append(notInIdaSymbolDict)

    if isDebugRsIDADiff:
      curDateTimeStr = getCurDatetimeStr()
      # curOutputFolder = os.path.join(curFolder, "output")
      curOutputFolder = os.path.join(curFolder, "debug")

      notInIdaObjcSymFilename = "%s_notInIdaObjcSymDictList_%s.json" % (appName, curDateTimeStr)
      notInIdaObjcSymFullPath = os.path.join(curOutputFolder, notInIdaObjcSymFilename)
      saveJsonToFile(notInIdaObjcSymFullPath, symbolDictList_objcNotInIda)
      # print("objcNotInIda count=%d" % len(symbolDictList_objcNotInIda))

      rsIdaSameAddrNotSameNameFilename = "%s_rsIdaSameAddrNotSameName_%s.json" % (appName, curDateTimeStr)
      rsIdaSameAddrNotSameNameFullPath = os.path.join(curOutputFolder, rsIdaSameAddrNotSameNameFilename)
      saveJsonToFile(rsIdaSameAddrNotSameNameFullPath, symbolDictList_rsIdaSameAddrNotSameName)
      # print("rsIdaSameAddrNotSameName count=%d" % len(symbolDictList_rsIdaSameAddrNotSameName))


    print("  Total restored objc symbol number: %s" % rsObjcSymbolNum)
    print("   in IDA: %s" % SymbolNum_RsInIda)
    print("     same name: %s" % SymbolNum_RsInIda_AddrSame)
    print("     not same name: %s" % SymbolNum_RsInIda_AddrNotSame)
    print("       known case: %s" % SymbolNum_RsInIda_AddrNotSame_knownCase)
    print("       unknown case: %s" % SymbolNum_RsInIda_AddrNotSame_unknownCase)
    print("   not in IDA: %s" % SymbolNum_RsNotInIda)

  if blockSymbolFile:
    print("%s Merge IDA scanned objc block symbols %s" % (mainDelimiter , mainDelimiter))
    print("  Block symbols file: %s" % blockSymbolFile)

    blockSymbolList = loadJsonFromFile(blockSymbolFile)
    blockSymbolNum = len(blockSymbolList)
    print("  blockSymbolNum=%s" % blockSymbolNum)

    # Note: above symbol list have changed, so need updated
    mergedSymbolsDictKeys = mergedSymbolsDict.keys()

    SymbolNum_BlockInMerged = 0
    SymbolNum_BlockInMerged_NameSame = 0
    SymbolNum_BlockInMerged_NameNotSame = 0
    SymbolNum_BlockNotInMerged = 0
    for blockSymDict in blockSymbolList:
      blockSymName = blockSymDict["name"]
      blockSymAddrStr = blockSymDict["address"]
      blockSymAddr = int(blockSymAddrStr, base=16)

      if blockSymAddr in mergedSymbolsDictKeys:
        SymbolNum_BlockInMerged += 1
        mergedSymDict = mergedSymbolsDict[blockSymAddr]
        mergedSymName = mergedSymDict["name"]
        if (blockSymName == mergedSymName):
          # if same name -> use/keep merged symbol
          SymbolNum_BlockInMerged_NameSame += 1
        else:
          print("Same addr=0x%X, but diff name: block=%s, merged=%s" % (blockSymAddr, blockSymName, mergedSymName))
          SymbolNum_BlockInMerged_NameNotSame += 1
      else:
        SymbolNum_BlockNotInMerged += 1

        mergedSymbolsDict[blockSymAddr] = {
          "name": blockSymName,
        }

    print("  Total block symbol number: %s" % blockSymbolNum)
    print("    in merged: %s" % SymbolNum_BlockInMerged)
    print("      same name: %s" % SymbolNum_BlockInMerged_NameSame)
    print("      not same name: %s" % SymbolNum_BlockInMerged_NameNotSame)
    print("    not in merged: %s" % SymbolNum_BlockNotInMerged)


  if outputSymbolFile:
    print("%s Output merged symbols %s" % (mainDelimiter , mainDelimiter))
    curOutputFolder = os.path.join(curFolder, "output")
    print("  Output folder: %s" % curOutputFolder)
    outputSymbolFullPath = os.path.join(curOutputFolder, outputSymbolFile)

    outputSymbolList = []
    for symAddr, symDict in mergedSymbolsDict.items():
      outputSymAddrStr = "0x%X" % symAddr
      outputSymName = symDict["name"]
      outputSymDict = {
        "name": outputSymName,
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
    saveJsonToFile(outputSymbolFullPath, sortedOutputSymbolList)
    print("  Exported complete")


if __name__ == "__main__":
  newParser = argparse.ArgumentParser()
  newParser.add_argument("-a", "--app-name", type=str, dest="appName", default=None, help="app name")
  # newParser.add_argument("-d", "--ida-symbol-file", type=str, required=True, dest="idaSymbolFile", default=None, help="IDA (Functions, Names) symbol file")
  newParser.add_argument("-d", "--ida-symbol-file", type=str, dest="idaSymbolFile", default=None, help="IDA (Functions, Names) symbol file")
  newParser.add_argument("-c", "--objc-symbol-file", type=str, dest="objcSymbolFile", default=None, help="ObjC symbol file")
  newParser.add_argument("-b", "--block-symbol-file", type=str, dest="blockSymbolFile", default=None, help="Block symbol file")
  newParser.add_argument("-o", "--output-symbol-file", type=str, dest="outputSymbolFile", default=None, help="Output merged symbol file")
  args = newParser.parse_args()
  print("%s Parsing input arguments %s" % (mainDelimiter , mainDelimiter))
  print("args=%s" % args)

  # # for debug
  # # curFolder = "/Users/crifan/dev/dev_src/ios_reverse/symbol/restore-symbol/crifan/restore-symbol"
  # print("curFolder=%s" % curFolder)
  # args.appName="WhatsApp"
  # args.idaSymbolFile="input/WhatsApp/WhatsApp_IDASymbols_FunctionsNames_20231125_222058.json"
  # args.objcSymbolFile="input/WhatsApp/WhatsApp_objcNoDupSymbols_20231105.json"
  # # args.idaSymbolFile = os.path.join(curFolder, "tools/mergeSymbols", args.idaSymbolFile)
  # # args.objcSymbolFile = os.path.join(curFolder, "tools/mergeSymbols", args.objcSymbolFile)
  # args.idaSymbolFile = os.path.join(curFolder, args.idaSymbolFile)
  # args.objcSymbolFile = os.path.join(curFolder, args.objcSymbolFile)

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
