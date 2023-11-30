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
#define RESTORE_SYMBOL_BASE_VERSION "1.1 (64 bit)"

#ifdef DEBUG
#define RESTORE_SYMBOL_VERSION RESTORE_SYMBOL_BASE_VERSION //" (Debug version compiled " __DATE__ " " __TIME__ ")"
#else
#define RESTORE_SYMBOL_VERSION RESTORE_SYMBOL_BASE_VERSION
#endif

//#define RS_OPT_DISABLE_OC_DETECT 1
//#define RS_OPT_VERSION 2
//#define RS_OPT_isReplaceRestrict 3

#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

void restore_symbol(NSString * inpath, NSString *outpath, NSString* outputObjcSymbolPath, NSString *jsonPath, bool isScanObjcSymbols, bool isOverwriteOutputFile, bool isReplaceRestrict);

void print_usage(void)
{
    fprintf(stderr,
            "\n"
            "restore-symbol %s\n"
            "\n"
            "Usage: restore-symbol -o <output-file> [-j <json-symbol-file>] <mach-o-file>\n"
            "\n"
            "  where options are:\n"
            "    -o,--output <output-file>                              New mach-o-file path\n"
            "    -s,--scan-objc-symbols <true/false>                    true/false to enable/disable to disable scan objc symbols\n"
            "    -e,--export-objc-symbol <output-objc-symbol-file>      Export ObjC symbol file while restore ObjC symbol\n"
            "    --replace-restrict                                     New mach-o-file will replace the LC_SEGMENT(__RESTRICT,__restrict)\n"
            "                                                           with LC_SEGMENT(__restrict,__restrict) to close dylib inject protection\n"
            "    -j,--json <json-symbol-file>                           Json file containing extra symbol info, the key is \"name\",\"address\"\n                                   like this:\n                               \n"
            "                                    [\n                                         {\n                                          \"name\": \"main\", \n                                          \"address\": \"0xXXXXXX\"\n                                         }, \n                                         {\n                                          \"name\": \"-[XXXX XXXXX]\", \n                                          \"address\": \"0xXXXXXX\"\n                                         },\n                                         .... \n                                        ]\n"
            "    -h,--help                      Print this help info then exit\n"

            ,
            RESTORE_SYMBOL_VERSION
            );
}

int main(int argc, char * argv[]) {
//    bool oc_detect_enable = true;
    bool isReplaceRestrict = false;
    bool isScanObjcSymbols = true;
    bool isOverwriteOutputFile = false;

    NSString *inpath = nil;
    NSString *outpath = nil;
    NSString *jsonPath = nil;
    NSString *outputObjcSymbolPath = nil;
    
    BOOL shouldPrintVersion = NO;
    BOOL isOnlyPrintHelp = NO;

    int longOptionChar;

    struct option longopts[] = {
        { "help",                       no_argument,       NULL, 'h' },
        { "version",                    no_argument,       NULL, 'v' },
        { "replace-restrict",           no_argument,       NULL, 'r' },
        { "export-objc-symbols",        required_argument, NULL, 'e' },
        { "json",                       required_argument, NULL, 'j' },
        { "output",                     required_argument, NULL, 'o' },
        { "scan-objc-symbols",          required_argument, NULL, 's' },
        { "overwrite-output-file",      required_argument, NULL, 'w' },

        { NULL,                      0,                 NULL, 0 },
    };

    if (argc == 1) {
        print_usage();
        exit(0);
    }

    while ( (longOptionChar = getopt_long(argc, argv, "e:j:o:s:w:hv", longopts, NULL)) != -1) {
        // printf("longOptionChar=%c, optarg=%s\n", longOptionChar, optarg);
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
            case 'e':
                outputObjcSymbolPath = [NSString stringWithUTF8String: optarg];
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
            case 'r':
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

//    restore_symbol(inpath, outpath, outputObjcSymbolPath, jsonPath, oc_detect_enable, isReplaceRestrict);
    restore_symbol(inpath, outpath, outputObjcSymbolPath, jsonPath, isScanObjcSymbols, isOverwriteOutputFile, isReplaceRestrict);
}
