# Function: IDA script plugin, export symbol from IDA
# Author: Crifan Li
# Update: 20231112

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
from idaapi import PluginForm
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

################################################################################
# Main
################################################################################

idaVersion = idaapi.IDA_SDK_VERSION
print("idaVersion=%s" % idaVersion)

idaRootFilename = get_root_filename()
print("idaRootFilename=%s" % idaRootFilename)

outputFilename = "IDAFunctionsSymbol"
# outputFullFilename = "%s_%s_%s.json" % (getFilenameNoPointSuffix(__file__), outputFilename, getCurDatetimeStr())
outputFullFilename = "%s_%s_%s.json" % (idaRootFilename, outputFilename, getCurDatetimeStr())
print("outputFullFilename=%s" % outputFullFilename)

symbolDictList = []

functionIterator = idautils.Functions()
# print("type(functionList)=%s" % type(functionList))
print("="*30 + "IDA All Functions Symbols:" + "="*30)
funNum = 1
for curFunc in functionIterator:
  # print("curFunc=%s" % curFunc)
  # curFuncAddrStr = hex(curFunc)
  curFuncAddrStr = "0x%X" % curFunc
  curFuncName = idc.get_func_name(curFunc)
  # print("curFuncName=%s" % curFuncName)
  # print("[%d] addr=0x%X, name=%s" % (funNum, curFunc, curFuncName))
  # print("[%d] addr=%s, name=%s" % (funNum, curFuncAddrStr, curFuncName))
  # curFuncFlags = idc.get_func_flags(curFunc)
  # curFuncComments = idc.get_func_cmt(curFunc, repeatable=0)
  curFuncAttr_start = idc.get_func_attr(curFunc, attr=FUNCATTR_START)
  curFuncAttr_end = idc.get_func_attr(curFunc, attr=FUNCATTR_END)
  # curFuncAttr_owner = idc.get_func_attr(curFunc, attr=FUNCATTR_OWNER)
  # print("[%d] addr=%s, name=%s, flags=0x%s, comments=%s, attr=[start=%s, end=%s, owner=%s]" % (funNum, curFuncAddrStr, curFuncName, curFuncFlags, curFuncComments, curFuncAttr_start, curFuncAttr_end, curFuncAttr_owner))
  # print("[%d] addr=%s, name=%s, flags=0x%s, attr=[start=0x%X, end=0x%X, owner=0x%X]" % (funNum, curFuncAddrStr, curFuncName, curFuncFlags, curFuncAttr_start, curFuncAttr_end, curFuncAttr_owner))
  curFuncSize = curFuncAttr_end - curFuncAttr_start
  curFuncSizeStr = "0x%X" % curFuncSize
  print("[%d] addr=%s, name=%s, size=%s" % (funNum, curFuncAddrStr, curFuncName, curFuncSizeStr))

  funNum += 1

  # # for debug 
  # if funNum == 200:
  #   llllll

  curSymbolDict = {
    "name": curFuncName,
    "address": curFuncAddrStr,
    "size": curFuncSizeStr,
  }

  symbolDictList.append(curSymbolDict)

symbolNum = len(symbolDictList)
print("Exporting %d symbols to file %s" % (symbolNum, outputFullFilename))
saveJsonToFile(outputFullFilename, symbolDictList)
