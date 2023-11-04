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
            fprintf(stderr, "process: %d/%ld\n", curIdx, symbols.count);
        }

        RSSymbol* curSymbol  = symbols[curIdx];
        if ([_symbols containsObject:curSymbol]){
            if (curSymbol.type & N_EXT) {
                self.extSymbolSize -= 1;
            } else {
                self.locSymbolSize -= 1;
            }

//            // for debug
//            uint8_t type = curSymbol.type;
//            if ( (type != 0x20) && (type != 0x24) && (type != 0x26) ) {
//                fprintf(stderr, "Removed [%d] type=0x%02X, address=0x%llX, name=%s\n", curIdx, type, curSymbol.address, [curSymbol.name UTF8String]);
//            }

            [realToRemoveSymbolList addObject: curSymbol];
        } else {
            fprintf(stderr, "Not remove not existed symbol: type=0x%02X, address=0x%llX, name=%s\n", curSymbol.type, curSymbol.address, [curSymbol.name UTF8String]);
        }
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
        if ((sym1.type & N_EXT) && (sym2.type & N_EXT)) {
            return sym1.type > sym2.type;
        } else if ((sym1.type & N_EXT) || (sym2.type & N_EXT)) {
            if (sym1.type & N_EXT) {
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
        
        
        if (is32Bit) {
            struct nlist * list = nlistsData.mutableBytes;
            bool isThumb = symbol.address & 1;
            list[i].n_desc = isThumb ? N_ARM_THUMB_DEF : 0;
            list[i].n_type = symbol.type;
            list[i].n_sect = symbol.address ? [self n_sectForAddress:symbol.address] : 0;
            list[i].n_value = (uint32_t)symbol.address & ~ 1;
            list[i].n_un.n_strx = origin_string_table_size + (uint32)symbolNames.length;
            
        } else {
            struct nlist_64 * list = nlistsData.mutableBytes;
            list[i].n_desc =  0;
            list[i].n_type = symbol.type;
            list[i].n_sect = symbol.address ? [self n_sectForAddress:symbol.address] : 0;
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
    

    uint8 n_sect = 0;
    
    for (id loadCommand in _machOFile.loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]]){
            CDLCSegment * seg = (CDLCSegment *)loadCommand;
            if(![loadCommand containsAddress:address]) {
                n_sect += [[seg sections] count];
            } else {
                for (CDSection * section in [seg sections]){
                    n_sect ++;
                    if ([section containsAddress:address]) {
                        return n_sect;
                    }
                    
                }
                
            }
        }
    }
    
    NSLog(@"Address(%llx) not found in the image", address);
    exit(1);
    return 1;
}


@end
