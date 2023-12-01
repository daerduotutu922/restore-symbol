//
//  RSSymbolCollector.m
//  restore-symbol
//
//  Created by EugeneYang on 16/8/19.
//
//

#import "RSSymbolCollector.h"

#import <mach-o/nlist.h>
#import "CDLCSymbolTable.h"
#import "CDLCSegment.h"
#import "CDSection.h"

@implementation RSSymbolCollector

- (instancetype)init
{
    self = [super init];
    if (self) {
        _symbols = [NSMutableArray array];
    }
    return self;
}

- (void)removeSymbol:(RSSymbol *)symbol{
    if ([_symbols containsObject:symbol]){
        if (symbol.type & N_EXT) {
            self.extSymbolSize -= 1;
        } else {
            self.locSymbolSize -= 1;
        }
        
        [_symbols removeObject: symbol];
    }
}

- (void)removeSymbols:(NSArray<RSSymbol *> *)symbols{
    // Method 1: use removeObjectsInArray
    NSMutableArray* realToRemoveSymbolList = [NSMutableArray array];
    long oneTenth = symbols.count / 10;

    for(int curIdx=0; curIdx < symbols.count; curIdx++){
        if ( (curIdx > 0) && (curIdx % oneTenth == 0) ) {
            fprintf(stderr, "  process: %d/%ld\n", curIdx, symbols.count);
        }

        RSSymbol* curSymbol  = symbols[curIdx];
        
        // follow code: speed too slow, temp not use it

//        if ([_symbols containsObject:curSymbol]){
//            if (curSymbol.type & N_EXT) {
//                self.extSymbolSize -= 1;
//            } else {
//                self.locSymbolSize -= 1;
//            }
//
////            // for debug
////            uint8_t type = curSymbol.type;
////            if ( (type != 0x20) && (type != 0x24) && (type != 0x26) ) {
////                fprintf(stderr, "Removed [%d] type=0x%02X, address=0x%llX, name=%s\n", curIdx, type, curSymbol.address, [curSymbol.name UTF8String]);
////            }
//
//            [realToRemoveSymbolList addObject: curSymbol];
//        } else {
//            fprintf(stderr, "Not remove not existed symbol: type=0x%02X, address=0x%llX, name=%s\n", curSymbol.type, curSymbol.address, [curSymbol.name UTF8String]);
//        }
        
        //TODO: after test, roll back normal logic
        // for debug
        self.locSymbolSize -= 1;
        [realToRemoveSymbolList addObject: curSymbol];
    }

    [_symbols removeObjectsInArray: realToRemoveSymbolList];
    fprintf(stderr, "removed %ld symbols\n", [realToRemoveSymbolList count]);

//    // Method 2: remove one by one
//    for(int curIdx=0; curIdx < symbols.count; curIdx++){
//        RSSymbol* curSymbol  = symbols[curIdx];
//        [self removeSymbol: curSymbol];
//        // for debug
//        uint8_t type = curSymbol.type;
//        if ( (type != 0x20) && (type != 0x24) && (type != 0x26) ) {
//            fprintf(stderr, "Removed [%d] type=0x%02X, address=0x%llX, name=%s\n", curIdx, type, curSymbol.address, [curSymbol.name UTF8String]);
//        }
//    }
}

- (void)addSymbol:(RSSymbol *)symbol{
    if (symbol == nil) {
        return ;
    }
    
    if (symbol.type & N_EXT) {
        self.extSymbolSize += 1;
    } else {
        self.locSymbolSize += 1;
    }
    [_symbols addObject:symbol];
}

- (void)addSymbols:(NSArray<RSSymbol *> *)symbols{
    if (symbols == nil)
        return ;
    self.locSymbolSize += symbols.count;
    [_symbols addObjectsFromArray:symbols];
}

- (void)generateAppendStringTable:(NSData **)stringTable appendSymbolTable:(NSData **)symbolTable{
    self.symbols = [self.symbols sortedArrayUsingComparator:^NSComparisonResult(RSSymbol * sym1, RSSymbol * sym2) {
        bool isSym1External = (sym1.type & N_EXT) > 0;
        bool isSym2External = (sym2.type & N_EXT) > 0;
        if (isSym1External && isSym2External) {
            return sym1.type > sym2.type;
        } else if (isSym1External || isSym2External) {
            if (isSym1External) {
                return NSOrderedDescending;
            } else {
                return NSOrderedAscending;
            }
        } else {
            return sym1.type > sym2.type;
        }
    }];
    
    const bool is32Bit = ! _machOFile.uses64BitABI;
    NSMutableData * symbolNames = [NSMutableData new];
    NSMutableData * nlistsData = [NSMutableData dataWithLength:_symbols.count * ( is32Bit ? sizeof(struct nlist) : sizeof(struct nlist_64))];
    memset(nlistsData.mutableBytes, 0, nlistsData.length);
    uint32 origin_string_table_size = _machOFile.symbolTable.strsize;

    for (int i = 0; i < _symbols.count; i ++) {
        RSSymbol * symbol = _symbols[i];
//        if (symbol.address == 0) {
//            continue;
//        }
        
        uint8 addrSect = [self n_sectForAddress:symbol.address];
        uint8_t nSect = symbol.address ? addrSect : 0;

        if (is32Bit) {
            struct nlist * list = nlistsData.mutableBytes;
            bool isThumb = symbol.address & 1;
            list[i].n_desc = isThumb ? N_ARM_THUMB_DEF : 0;
            list[i].n_type = symbol.type;
            list[i].n_sect = nSect;
            list[i].n_value = (uint32_t)symbol.address & ~ 1;
            list[i].n_un.n_strx = origin_string_table_size + (uint32)symbolNames.length;
        } else {
            struct nlist_64 * list = nlistsData.mutableBytes;
            list[i].n_desc =  0;
            list[i].n_type = symbol.type;
            list[i].n_sect = nSect;
            list[i].n_value = symbol.address;
            list[i].n_un.n_strx = origin_string_table_size + (uint32)symbolNames.length;
        }

        [symbolNames appendBytes:symbol.name.UTF8String length:symbol.name.length];
        [symbolNames appendBytes:"\0" length:1];
    }

    *stringTable = symbolNames;
    *symbolTable = nlistsData;
}

- (uint8)n_sectForAddress:(uint64)address{
    BOOL isValidInSegmentButNotInAnySection = FALSE;
    CDLCSegment* addrInsideSeg = NULL;

    // for debug
    bool isNeedDebug = false;
//    if (0x102EAC12C == address){
//    if (0x103A86DD0 == address){
//    if (0x100000000 == address){
//        isNeedDebug = true;
//        NSLog(@"debug: 0x%llX", address);
//    }

    uint8 n_sect = 0;
    for (id loadCommand in _machOFile.loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]]){
            CDLCSegment* seg = (CDLCSegment *)loadCommand;
//            NSUInteger segVmaddr = [seg vmaddr];
//            NSUInteger segFilesize = [seg filesize];
//            uint64_t segStartAddr = (uint64_t)segVmaddr;
//            uint64_t segEndAddr = segStartAddr + (uint64_t)segFilesize;
//            BOOL isValidAddrInSeg = (address >= segStartAddr) && (address < segEndAddr);

            if (isNeedDebug){
                NSLog(@"segment=%@", seg);
//                NSLog(@"  segment addr: [0x%llX-0x%llX] => isValidAddrInSeg=%d", segStartAddr, segEndAddr, isValidAddrInSeg);
            }

            bool isValidAddrInSeg = [seg containsAddress:address];
            if(isValidAddrInSeg) {
                for (CDSection * section in [seg sections]){
                    if (isNeedDebug){
                        NSLog(@"section=%@", section);
                    }

                    n_sect ++;
                    if ([section containsAddress:address]) {
                        return n_sect;
                    }
                }
                
                isValidInSegmentButNotInAnySection = TRUE;
                addrInsideSeg = seg;
            } else {
                if (isNeedDebug){
                    NSLog(@"Not contain address 0x%llX for segment: %@", address, seg);
                }

                n_sect += [[seg sections] count];
            }
        } else {
            if (isNeedDebug){
                NSLog(@"Omit check for non CDLCSegment: %@", loadCommand);
            }
        }
    }
    
    if(isValidInSegmentButNotInAnySection){
        // for valid address in segment, but not in any section
        // eg: 0x100000000, 0x100000FA4, ...
        // return n_sect=0
        n_sect = 0;
        if (isNeedDebug){
            NSLog(@"return n_sect=0 for address 0x%llX, valid in segment %@, but not inside any section", address, addrInsideSeg);
        }
        return n_sect;
    } else {
        NSLog(@"Address (0x%llx) not found in the image", address);
        exit(1);
        return 1;
    }
}

@end
