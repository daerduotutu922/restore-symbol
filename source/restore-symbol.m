//
//  main.m
//  restore-symbol
//
//  Created by EugeneYang on 16/8/16.
//
//

#import <Foundation/Foundation.h>
#include <sys/types.h>
#include <sys/stat.h>
#import <mach-o/nlist.h>
#import "CDFile.h"
#import "CDMachOFile.h"
#import "CDLCSymbolTable.h"
#import "CDLCSegment.h"
#import "CDSymbol.h"
#import "CDLCDynamicSymbolTable.h"
#import "CDLCLinkeditData.h"
#import "CDClassDump.h"
#import "CDFindMethodVisitor.h"
#import "RSScanMethodVisitor.h"
#import "CDFatFile.h"

#define IntSize (Is32Bit? sizeof(uint32_t) : sizeof(uint64_t) )
#define NListSize (Is32Bit? sizeof(struct nlist) : sizeof(struct nlist_64) )


#define vm_addr_round(v,r) ( (v + (r-1) ) & (-r) )


//void restore_symbol(NSString * inpath, NSString *outpath, NSString* outputObjcSymbolPath, NSString *jsonPath, bool oc_detect_enable, bool replace_restrict){
void restore_symbol(NSString * inpath, NSString *outpath, NSString* outputObjcSymbolPath, NSString *jsonPath, bool scanObjcSymbols, bool replace_restrict){
    if (![[NSFileManager defaultManager] fileExistsAtPath:inpath]) {
        fprintf(stderr, "Error: Input file doesn't exist!\n");
        exit(1);
    }
    
    if (jsonPath.length != 0 && ![[NSFileManager defaultManager] fileExistsAtPath:jsonPath]) {
        fprintf(stderr, "Error: Json file doesn't exist!\n");
        exit(1);
    }
    
    if ([outpath length] == 0) {
        fprintf(stderr, "Error: No output file path!\n");
        exit(1);
    }
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:outpath]) {
        fprintf(stderr, "Error: Output file has exist!\n");
        exit(1);
    }
    
    fprintf(stderr, "=========== Start =============\n");

    NSMutableData * outData = [[NSMutableData alloc] initWithContentsOfFile:inpath];
    CDFile * ofile = [CDFile fileWithContentsOfFile:inpath searchPathState:nil];
    
    if ([ofile isKindOfClass:[CDFatFile class]] ) {
        fprintf(stderr,"Restore-symbol supports armv7 and arm64 archtecture, but not support fat file. Please use lipo to thin the image file first.");
        exit(1);
    }
    
    CDMachOFile * machOFile = (CDMachOFile *)ofile;
    const bool Is32Bit = ! machOFile.uses64BitABI;
    
    RSSymbolCollector *collector = [RSSymbolCollector new];
    collector.machOFile = machOFile;
    
//    if (oc_detect_enable) {
    if (scanObjcSymbols) {
        fprintf(stderr, "Scan ObjC method in mach-o-file: %s\n", [inpath UTF8String]);

        CDClassDump *classDump = [[CDClassDump alloc] init];
        CDArch targetArch;
        if ([machOFile bestMatchForLocalArch:&targetArch] == NO) {
            fprintf(stderr, "Error: Couldn't get local architecture!\n");
            exit(1);
        }

        classDump.targetArch = targetArch;
        [classDump processObjectiveCData];
        [classDump registerTypes];
        
        NSError *error;
        if (![classDump loadFile:machOFile error:&error]) {
            fprintf(stderr, "Error: %s\n", [[error localizedFailureReason] UTF8String]);
            exit(1);
        } else {
            [classDump processObjectiveCData];
            [classDump registerTypes];
            
            RSScanMethodVisitor *visitor = [[RSScanMethodVisitor alloc] initWithSymbolCollector:collector];
            visitor.classDump = classDump;
            [classDump recursivelyVisit:visitor];
        }
        
        fprintf(stderr, "Scan ObjC method finish.\n");

        NSArray<RSSymbol *> * objcSymbolArr = collector.symbols;
        NSUInteger objCSymbolCount = objcSymbolArr.count;
        fprintf(stderr, "Scanned %ld objc symbols\n", objCSymbolCount);

        fprintf(stderr, "Detecting duplicated symbols ...\n");

        NSMutableArray* omittedSymList = [NSMutableArray array];
        //    NSDictionary<NSString *, id> *noDupSymDict;
        NSMutableDictionary* noDupSymDict = [NSMutableDictionary dictionary];
        for (NSUInteger symIdx = 0; symIdx < objCSymbolCount; symIdx++) {
            RSSymbol* curSymbol = objcSymbolArr[symIdx];
            uint64 address = curSymbol.address;

            NSString* name = curSymbol.name;
            const char* nameStr = [name UTF8String];
            uint8_t type = curSymbol.type;

    //        // for debug
    //        if ( ([name isEqualToString: @"-[_TtC13WAHistorySync17HistorySyncDevice isSyncing]"]) && (type == 0x0E) && (address == 0x1005D206C) ) {
    //            fprintf(stderr, "Odd symbol (check but not exist): [%ld] type=0x%02X, address=0x%llX, name=%s\n", symIdx, type, address, nameStr);
    //        }

            BOOL needAdd = false;

            if (address != 0) {
                id existSymbolDict = [noDupSymDict objectForKey: name];
                if(existSymbolDict != nil){
                    NSNumber *existTypeNumber = [existSymbolDict valueForKey: @"type"];
                    char existType = [existTypeNumber charValue];
                    if (existType != N_SECT) {
                        needAdd = true;
                    } else if (type == N_SECT) {
                        // both is 0x0E -> but diff address
                        // eg:
                        //  type=0x0E, address=0x101449f50, name=-[_TtC13WAHistorySync17HistorySyncDevice isSyncing]
                        //  type=0x0E, address=0x1005D206C, name=-[_TtC13WAHistorySync17HistorySyncDevice isSyncing]
                        NSNumber *existAddressNumber = [existSymbolDict valueForKey: @"address"];
                        uint64 existAddress = [existAddressNumber longLongValue];
                        if (address != existAddress){
    //                        needAdd = true;
                            fprintf(stderr, "[%ld] Strage (same name and type, but diff address): type=0x%02X, name=%s -> current address=0x%llX vs existed: address=0x%llX\n", symIdx, type, nameStr, address, existAddress);
                        }
                    }
                } else {
                    needAdd = true;
                }
            }
            
            if(needAdd) {
                NSNumber *addressNumber = [NSNumber numberWithUnsignedLongLong: address];
                NSNumber *typeNumber = [NSNumber numberWithChar: type];
                NSMutableDictionary* curAddressTypeDict = [NSMutableDictionary dictionaryWithObjectsAndKeys: addressNumber, @"address", typeNumber, @"type", nil];
                [noDupSymDict setObject:curAddressTypeDict forKey:name];
//                NSLog(@"Added: type=0x%02X, address=0x%llX, name=%@", [typeNumber intValue], [addressNumber longLongValue], name);
//                fprintf(stderr, "Added [%ld] type=0x%02X, address=0x%llX, name=%s\n", symIdx, type, address, nameStr);
            } else {
//                fprintf(stderr, "Omit  [%ld] type=0x%02X, address=0x%llX, name=%s\n", symIdx, type, address, nameStr);
                [omittedSymList addObject:curSymbol];
            }
        }

        NSUInteger noDumpObjCSymCount = [[noDupSymDict allKeys] count];
        NSUInteger omittedObjCSymCount = [omittedSymList count];
        fprintf(stderr, "non-duplicated symbols: %ld, to remove duplicated symbols: %ld\n", noDumpObjCSymCount, omittedObjCSymCount);

        fprintf(stderr, "removing duplicated symbols ...\n");
        [collector removeSymbols: omittedSymList];

        NSUInteger noDupObjCSymbolCount = [collector.symbols count];
        fprintf(stderr, "restore non-duplicated %ld symbols\n", noDupObjCSymbolCount);

    //    NSLog(@"collector.symbols to json valid: %d", [NSJSONSerialization isValidJSONObject: collector.symbols]);
    //    NSLog(@"noDupSymDict to json valid: %d", [NSJSONSerialization isValidJSONObject: noDupSymDict]);

        // convert to valid json object
        NSMutableArray* validObjcSymJsonList = [NSMutableArray array];
        for (NSUInteger symIdx = 0; symIdx < [collector.symbols count]; symIdx++) {
            RSSymbol* curSymbol = collector.symbols[symIdx];
            NSString *addressStr = [NSString stringWithFormat:@"0x%llX", [curSymbol address]];
            NSString *typeStr = [NSString stringWithFormat:@"0x%02X", [curSymbol type]];
            NSMutableDictionary* curJsonItemDict = [NSMutableDictionary dictionaryWithObjectsAndKeys: [curSymbol name], @"name", addressStr, @"address", typeStr, @"type", nil];
            [validObjcSymJsonList addObject: curJsonItemDict];
        }
//        NSLog(@"validObjcSymJsonList to json valid: %d", [NSJSONSerialization isValidJSONObject: validObjcSymJsonList]);

    //    id toJsonObj = collector.symbols;
    //    id toJsonObj = objcJsonSymList;
    //    id toJsonObj = noDupSymDict;
        id toJsonObj = validObjcSymJsonList;
        NSError* toJsonErr = nil;
        NSData* objcSymJsonData = [NSJSONSerialization dataWithJSONObject: toJsonObj options: NSJSONWritingPrettyPrinted error: &toJsonErr];
        NSString *objcSymJsonStr = [[NSString alloc] initWithData:objcSymJsonData encoding:NSUTF8StringEncoding];
        fprintf(stderr, "objc symbol json string: %s\n", [objcSymJsonStr UTF8String]);
        fprintf(stderr, "Writing objc symbol json string into file: %s\n", [outputObjcSymbolPath UTF8String]);
        NSError* writeJsonFileErr = nil;
        [objcSymJsonStr writeToFile:outputObjcSymbolPath atomically:YES encoding:NSUTF8StringEncoding error:&writeJsonFileErr];
        fprintf(stderr, "Complete export objc symbol to json file: %s\n", [outputObjcSymbolPath UTF8String]);
    }

    if (jsonPath != nil && jsonPath.length != 0) {
        fprintf(stderr, "Parse symbols in json file: %s\n", [jsonPath UTF8String]);
        NSData * jsonData = [NSData dataWithContentsOfFile:jsonPath];
        if (jsonData == nil) {
            fprintf(stderr, "Can't load json data.\n");
            exit(1);
        }

        NSArray *jsonSymbols = [RSSymbol symbolsWithJson:jsonData];
        if (jsonSymbols == nil) {
            fprintf(stderr,"Error: Json file cann't parse!");
            exit(1);
        } else {
            fprintf(stderr, "Parsed %ld symbols from json file\n", [jsonSymbols count]);
            [collector addSymbols:jsonSymbols];
        }
        fprintf(stderr, "Parse finish for symbols in json file.\n");
    }
    
    NSData *string_table_append_data = nil;
    NSData *symbol_table_append_data = nil;
    [collector generateAppendStringTable:&string_table_append_data appendSymbolTable:&symbol_table_append_data];
    
    uint32 increase_symbol_num = (uint32)collector.symbols.count;
    uint32 increase_size_string_tab = (uint32)string_table_append_data.length;
    uint32 increase_size_symtab = (uint32)symbol_table_append_data.length;
    uint32 increase_size_all_without_padding = increase_size_symtab + increase_size_string_tab;
    
    uint32 origin_string_table_offset = machOFile.symbolTable.stroff;
    uint32 origin_string_table_size = machOFile.symbolTable.strsize;
    uint32 origin_symbol_table_offset = machOFile.symbolTable.symoff;
    uint32 origin_symbol_table_num = machOFile.symbolTable.nsyms;
    
    uint32 origin_dysymbol_table_locsymbol_num = machOFile.dynamicSymbolTable.dysymtab.nlocalsym;

    if (replace_restrict){
        CDLCSegment * restrict_seg = [machOFile segmentWithName:@"__RESTRICT"];
        
        struct segment_command *restrict_seg_cmd = (struct segment_command *)((char *)outData.mutableBytes + restrict_seg.commandOffset);
        struct section *restrict_section = NULL;
        
        int cmd_size = (Is32Bit? sizeof(struct segment_command) : sizeof(struct segment_command_64));
        if (restrict_seg.cmdsize > cmd_size) {
            restrict_section = (struct section *)((char *)outData.mutableBytes + restrict_seg.commandOffset + cmd_size);
        }
        
        if (restrict_seg && restrict_section) {
            fprintf(stderr, "rename segment __RESTRICT  in mach-o header.\n");
            strncpy(restrict_seg_cmd -> segname, "__restrict", 16);
            strncpy(restrict_section -> segname, "__restrict", 16);
        } else {
            fprintf(stderr, "No section (__RESTRICT,__restrict) in mach-o header.\n");
        }
    }
    
    //LC_CODE_SIGNATURE need align 16 byte, so add padding at end of string table.
    uint32 string_table_padding = 0;
    {
        CDLCLinkeditData * codesignature = nil;
        for (CDLoadCommand *command in machOFile.loadCommands) {
            if (command.cmd == LC_CODE_SIGNATURE){
                codesignature = (CDLCLinkeditData *)command;
            }
        }
        
        if (codesignature) {
            struct linkedit_data_command *command = (struct linkedit_data_command *)((char *)outData.mutableBytes + codesignature.commandOffset);
            uint32_t tmp_offset =  command -> dataoff + increase_size_all_without_padding;
            uint32_t final_offset = vm_addr_round(tmp_offset, 16);
            
            string_table_padding = final_offset - tmp_offset;
            command -> dataoff = final_offset;
        }
    }
    
    
    {
        CDLCSymbolTable *symtab = [machOFile symbolTable];
        struct symtab_command *symtab_out = (struct symtab_command *)((char *)outData.mutableBytes + symtab.commandOffset);
        symtab_out -> nsyms += increase_symbol_num;
        symtab_out -> stroff += increase_size_symtab;
        symtab_out -> strsize += increase_size_string_tab + string_table_padding;
    }
    
    {
        CDLCDynamicSymbolTable *dysymtabCommand = [machOFile dynamicSymbolTable];
        struct dysymtab_command *command = (struct dysymtab_command *)((char *)outData.mutableBytes + dysymtabCommand.commandOffset);
        command -> nlocalsym += collector.locSymbolSize;
        command -> iextdefsym += collector.locSymbolSize;
        command -> nextdefsym += collector.extSymbolSize;
        command -> iundefsym += collector.locSymbolSize + collector.extSymbolSize;
        command -> indirectsymoff += increase_size_symtab;
    }


    {
        CDLCSegment * linkeditSegment = [machOFile segmentWithName:@"__LINKEDIT"];
        if (Is32Bit) {
            struct segment_command *linkedit_segment_command = (struct segment_command *)((char *)outData.mutableBytes + linkeditSegment.commandOffset);
            linkedit_segment_command -> filesize += increase_size_all_without_padding + string_table_padding;
            linkedit_segment_command -> vmsize = (uint32) vm_addr_round((linkedit_segment_command -> filesize), 0x4000);
        } else {
            struct segment_command_64 *linkedit_segment_command = (struct segment_command_64  *)((char *)outData.mutableBytes + linkeditSegment.commandOffset);
            linkedit_segment_command -> filesize += increase_size_all_without_padding + string_table_padding;
            linkedit_segment_command -> vmsize = vm_addr_round((linkedit_segment_command -> filesize), 0x4000);
        }
    }

    // must first insert string
    [outData replaceBytesInRange:NSMakeRange(origin_string_table_offset + origin_string_table_size , 0) withBytes:(const void *)string_table_append_data.bytes   length:increase_size_string_tab + string_table_padding];
    
    [outData replaceBytesInRange:NSMakeRange(origin_symbol_table_offset + origin_symbol_table_num * NListSize , 0) withBytes:(const void *)symbol_table_append_data.bytes   length:increase_size_symtab];
    
    NSError * err = nil;
    [outData writeToFile:outpath options:NSDataWritingWithoutOverwriting error:&err];
    
    if (!err) {
        chmod(outpath.UTF8String, 0755);
    }else{
        fprintf(stderr,"Write file error : %s\n", [err localizedDescription].UTF8String);
        return;
    }
    fprintf(stderr,"Output file: %s\n", outpath.UTF8String);

    fprintf(stderr,"=========== Finish ============\n");
}
