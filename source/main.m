//
//  main.m
//  class-dump
//
//  Created by EugeneYang on 16/8/22.
//
//

#include <stdio.h>

#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <mach-o/arch.h>

// #define RESTORE_SYMBOL_BASE_VERSION "1.0 (64 bit)"
#define RESTORE_SYMBOL_BASE_VERSION "2.0 (64 bit)"

#ifdef DEBUG
#define RESTORE_SYMBOL_VERSION RESTORE_SYMBOL_BASE_VERSION //" (Debug version compiled " __DATE__ " " __TIME__ ")"
#else
#define RESTORE_SYMBOL_VERSION RESTORE_SYMBOL_BASE_VERSION
#endif

void restore_symbol(NSString * inpath, NSString *outpath, NSString *jsonPath, bool isOverwriteOutputFile, bool isScanObjcSymbols, bool isRemoveDuplicatedObjcSymbols, NSString* objcSymbolsOutputFile, bool isRestoreSymbols, bool isReplaceRestrict);

void print_usage(void)
{
    char* jsonExampleStr =
    "                                                               [\n"
    "                                                                 {\n"
    "                                                                   \"name\": \"main\",\n"
    "                                                                   \"address\": \"0xXXXXXX\"\n"
    "                                                                 },\n"
    "                                                                 {\n"
    "                                                                   \"name\": \"-[XXXX XXXXX]\",\n"
    "                                                                   \"address\": \"0xXXXXXX\"\n"
    "                                                                 },\n"
    "                                                                 ...\n"
    "                                                               ]\n"
    ;
    
    fprintf(stderr,
            "\n"
            "restore-symbol %s\n"
            "\n"
            "Usage: restore-symbol [-o <output-file>] [-j <json-symbol-file>] [-w <true/false>] [-s <true/false>] [-b <objcSymbolsOutputFile>] [-r <true/false>] [-p] <input-mach-O-file>\n"
            "\n"
            "  where options are:\n"
            "    -h,--help                                              Print this help info then exit\n"
            "    -v,--version                                           Print version info then exit\n"
            "    -o,--output <output-file>                              New mach-O file path\n"
            "                                                             default: null\n"
            "    -j,--json <json-symbol-file>                           Json file containing extra symbol info, the key is \"name\",\"address\"\n"
            "                                                             like this:\n%s"
            "                                                             default: null\n"
            "    -w,--overwrite-output-file <true/false>                Overwrite output file if existed\n"
            "                                                             default: false\n"
            "    -s,--scan-objc-symbols <true/false>                    Scan objc symbols or not\n"
            "                                                             default: true\n"
            "    -m,--remove-duplicated-objc-symbols <true/false>       Remove duplicated objc symbols or not after scan objc symbols\n"
            "                                                             default: true\n"
            "    -b,--objc-symbols-output-file <objcSymbolsOutputFile>  Export objc symbols to file\n"
            "                                                             default: null\n"
            "    -r,--restore-symols <true/false>                       Restore symbol or not\n"
            "                                                             default: true\n"
            "    -p,--replace-restrict                                  New mach-O file will replace the LC_SEGMENT(__RESTRICT,__restrict)\n"
            "                                                             with LC_SEGMENT(__restrict,__restrict) to close dylib inject protection\n"
            "                                                             default: disabled\n"
            , RESTORE_SYMBOL_VERSION, jsonExampleStr);
}

int main(int argc, char * argv[]) {
    bool isScanObjcSymbols = true;
    bool isOverwriteOutputFile = false;
    bool isRestoreSymbols = true;
    bool isRemoveDuplicatedObjcSymbols = true;
    bool isReplaceRestrict = false;

    NSString *inpath = nil;
    NSString *outpath = nil;
    NSString *jsonPath = nil;
    NSString *objcSymbolsOutputFile = nil;
    
    BOOL shouldPrintVersion = NO;
    BOOL isOnlyPrintHelp = NO;

    int longOptionChar;

    struct option longopts[] = {
        { "help",                           no_argument,       NULL, 'h' },
        { "version",                        no_argument,       NULL, 'v' },
        { "output",                         required_argument, NULL, 'o' },
        { "json",                           required_argument, NULL, 'j' },
        { "overwrite-output-file",          required_argument, NULL, 'w' },
        { "scan-objc-symbols",              required_argument, NULL, 's' },
        { "remove-duplicated-objc-symbols", required_argument, NULL, 'm' },
        { "objc-symbols-output-file",       required_argument, NULL, 'b' },
        { "restore-symols",                 required_argument, NULL, 'r' },
        { "replace-restrict",               no_argument,       NULL, 'p' },

        { NULL,                      0,                 NULL, 0 },
    };

    if (argc == 1) {
        print_usage();
        exit(0);
    }

    while ( (longOptionChar = getopt_long(argc, argv, "hvo:j:w:s:m:b:r:p", longopts, NULL)) != -1) {
//        printf("longOptionChar=%c, optarg=%s\n", longOptionChar, optarg);
        switch (longOptionChar) {
            case 'h':
                isOnlyPrintHelp = YES;
                break;
            case 'v':
                shouldPrintVersion = YES;
                break;
            case 'o':
                outpath = [NSString stringWithUTF8String: optarg];
                break;
            case 'j':
                jsonPath = [NSString stringWithUTF8String: optarg];
                break;
            case 'w':
                if (strcmp(optarg, "true") == 0) {
                    isOverwriteOutputFile = true;
                } else if (strcmp(optarg, "false") == 0) {
                    isOverwriteOutputFile = false;
                } else {
                    printf("Invalid value %s for --overwrite-output-file\n", optarg);
                    isOnlyPrintHelp = true;
                }
                break;
            case 's':
                if (strcmp(optarg, "true") == 0) {
                    isScanObjcSymbols = true;
                } else if (strcmp(optarg, "false") == 0) {
                    isScanObjcSymbols = false;
                } else {
                    printf("Invalid value %s for --scan-objc-symbols\n", optarg);
                    isOnlyPrintHelp = true;
                }
                break;
            case 'm':
                if (strcmp(optarg, "true") == 0) {
                    isRemoveDuplicatedObjcSymbols = true;
                } else if (strcmp(optarg, "false") == 0) {
                    isRemoveDuplicatedObjcSymbols = false;
                } else {
                    printf("Invalid value %s for --remove-duplicated-objc-symbols\n", optarg);
                    isOnlyPrintHelp = true;
                }
                break;
            case 'b':
                objcSymbolsOutputFile = [NSString stringWithUTF8String: optarg];
                break;
            case 'r':
                if (strcmp(optarg, "true") == 0) {
                    isRestoreSymbols = true;
                } else if (strcmp(optarg, "false") == 0) {
                    isRestoreSymbols = false;
                } else {
                    printf("Invalid value %s for --restore-symols\n", optarg);
                    isOnlyPrintHelp = true;
                }
                break;
            case 'p':
                isReplaceRestrict = true;
                break;

            default:
                break;
        }
    }

    if (isOnlyPrintHelp) {
        print_usage();
        exit(0);
    }

    if (shouldPrintVersion) {
        printf("restore-symbol %s compiled %s\n", RESTORE_SYMBOL_VERSION, __DATE__ " " __TIME__);
        exit(0);
    }
    
    if (optind < argc) {
        inpath = [NSString stringWithUTF8String:argv[optind]];
    }

    restore_symbol(inpath, outpath, jsonPath, isOverwriteOutputFile, isScanObjcSymbols, isRemoveDuplicatedObjcSymbols, objcSymbolsOutputFile, isRestoreSymbols, isReplaceRestrict);
}
