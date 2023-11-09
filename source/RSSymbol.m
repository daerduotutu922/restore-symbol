//
//  RSSymbol.m
//  restore-symbol
//
//  Created by EugeneYang on 16/8/19.
//
//

#import "RSSymbol.h"

@implementation RSSymbol

- (NSString *)description
{
    NSString* origDesc = [super description];
    return [NSString stringWithFormat:@"%@ | name=%@, address=0x%llX, type=0x%02X", origDesc, [self name], [self address], [self type]];
}

+ (NSArray<RSSymbol *> *)symbolsWithJson:(NSData *)json{
    NSError * e = nil;
    
    NSArray *symbols = [NSJSONSerialization JSONObjectWithData:json options:NSJSONReadingMutableContainers error:&e];
    
    if (!symbols) {
        fprintf(stderr,"Parse json error!\n");
        fprintf(stderr,"%s\n", e.description.UTF8String);
        return nil;
    }
    
    NSMutableArray * parsedSymbolList = [NSMutableArray array];
    for (NSDictionary *dict in symbols) {
        unsigned long long address;
        NSString *addressStr = dict[RS_JSON_KEY_ADDRESS];
        NSScanner* addrScanner = [NSScanner scannerWithString: addressStr];
        [addrScanner scanHexLongLong:&address];

        RSSymbol * symbol = nil;
        NSString *typeStr = dict[RS_JSON_KEY_SYMBOL_TYPE];
        if (typeStr != nil) {
            unsigned int typeInt;
            NSScanner* typeScanner = [NSScanner scannerWithString: typeStr];
            [typeScanner scanHexInt: &typeInt];
            unsigned char type = (unsigned char)typeInt;
            symbol = [self symbolWithName:dict[RS_JSON_KEY_SYMBOL_NAME] address:address type:type];
        } else {
            symbol = [self symbolWithName:dict[RS_JSON_KEY_SYMBOL_NAME] address:address];
        }
//        NSLog(@"parsed symbol: %@", symbol);
        [parsedSymbolList addObject:symbol];
    }

//    NSLog(@"Parsed %ld symbols", [parsedSymbolList count]);
    return parsedSymbolList;
}


+ (RSSymbol *)symbolWithName:(NSString *)name address:(uint64)addr{
    RSSymbol * s = [RSSymbol new];
    s.name = name;
    s.address = addr;
    s.type = N_SECT;
    return s;
}

+ (RSSymbol *)symbolWithName:(NSString *)name address:(uint64)addr type:(uint8)type{
    RSSymbol * s = [RSSymbol new];
    s.name = name;
    s.address = addr;
    s.type = type;
    return s;
}
@end
