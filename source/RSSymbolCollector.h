//
//  RSSymbolCollector.h
//  restore-symbol
//
//  Created by EugeneYang on 16/8/19.
//
//

#import <Foundation/Foundation.h>
#import "RSSymbol.h"
#import "CDMachOFile.h"

@interface RSSymbolCollector : NSObject

@property (nonatomic, weak) CDMachOFile * machOFile;
@property (nonatomic, strong) NSMutableArray *symbols;
@property (nonatomic) unsigned long locSymbolSize;
@property (nonatomic) unsigned long extSymbolSize;

- (void)addSymbol:(RSSymbol *)symbol;
- (void)addSymbols:(NSArray<RSSymbol *> *)symbols;
- (void)removeSymbol:(RSSymbol *)symbol;
- (void)removeSymbols:(NSArray<RSSymbol *> *)symbols;

- (void)generateAppendStringTable:(NSData **)stringTable appendSymbolTable:(NSData **)nlist;
@end
