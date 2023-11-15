# restore-symbol

* Update: `20231115`
* Forked from: https://github.com/HeiTanBc/restore-symbol
* Changelog
  * 20231115
    * other updates for `exportIDASymbo.py`, `mergeSymbols.py`
  * 20231103
    * add `tools/IDAScripts/export_ida_symbol/exportIDASymbo.py`
      * to export IDA symbols
    * add `tools/mergeSymbols/mergeSymbols.py`
      * to merge all symbols from restore-symbol restored, exported from IDA functions list, scanned from IDA block
  * 20231027
    * `search_oc_block/ida_search_block.py`
      * Converted to support [IDA 7.4+](https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml) (`SegName`->`get_segm_name`, `Qword`->`get_qword`, etc.)
      * Converted to Python 3.x(`print xxx`->`print(xxx)`, `filter`->`list` etc.)
      * Fixed bug: `RecursionError: maximum recursion depth exceeded while calling a Python object`
* TODO
  * [ ] update `class-dump` to support new load command: `0x80000033`, `0x80000034`

---

A reverse engineering tool to restore stripped symbol table for iOS app.

Example: restore symbol for Alipay
![](picture/after_restore.jpeg)

## How to use

### Just restore symbol of oc method

- 1. Download source code and compile.

```bash
git clone --recursive https://github.com/crifan/restore-symbol.git
cd restore-symbol && make
./restore-symbol
```

- 2. Restore symbol using this command. It will output a new mach-o file with symbol.

```bash
./restore-symbol /pathto/origin_mach_o_file -o /pathto/mach_o_with_symbol 
```

- 3. Copy the new mach-o file (with symbol) to app bundle, replace the origin mach-o file with new mach-o file. Resign app bundle.

```bash
codesign -f -s - --timestamp=none --generate-entitlement-der --entitlement ./xxxx.app.xcent ./xxxx.app
```

- 4. Install the app bundle to iOS device, and use lldb to debug the app. Maybe you can use the ```ios-deploy```, or other way you like. If you use ```ios-deploy``` , you can execute this command.

```bash
brew install ios-deploy
ios-deploy -d -b xxxx.app
```

- 5. Now you can use ```b -[class method]``` to set breakpoint.

### Restore symbol of oc block

- 1. Search block symbol in IDA to get json symbol file, using script([`search_oc_block/ida_search_block.py`](./search_oc_block/ida_search_block.py)) .

![](http://blog.imjun.net/posts/restore-symbol-of-iOS-app/ida_result_position.png)

![](http://blog.imjun.net/posts/restore-symbol-of-iOS-app/ida_result_sample.jpg)

- 2. Use command line tool(restore-symbol) to inject oc method symbols and block symbols into mach o file.

```bash
./restore-symbol /pathto/origin_mach_o_file -o /pathto/mach_o_with_symbol -j /pathto/block_symbol.json
```

- 3. Other steps(resign, install, debug) are samen as above.

## Command Line Usage

```bash
# ./restore-symbol --help

restore-symbol 1.0 (64 bit)

Usage: restore-symbol -o <output-file> [-j <json-symbol-file>] <mach-o-file>

  where options are:
    -o,--output <output-file>                              New mach-o-file path
    -s,--scan-objc-symbols <true/false>                    true/false to enable/disable to disable scan objc symbols
    -e,--export-objc-symbol <output-objc-symbol-file>      Export ObjC symbol file while restore ObjC symbol
    --replace-restrict                                     New mach-o-file will replace the LC_SEGMENT(__RESTRICT,__restrict)
                                                           with LC_SEGMENT(__restrict,__restrict) to close dylib inject protection
    -j,--json <json-symbol-file>                           Json file containing extra symbol info, the key is "name","address"
                                   like this:
                               
                                    [
                                         {
                                          "name": "main", 
                                          "address": "0xXXXXXX"
                                         }, 
                                         {
                                          "name": "-[XXXX XXXXX]", 
                                          "address": "0xXXXXXX"
                                         },
                                         .... 
                                        ]
    -h,--help                      Print this help info then exit
```
