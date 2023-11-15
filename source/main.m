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


#define RESTORE_SYMBOL_BASE_VERSION "1.0 (64 bit)"

#ifdef DEBUG
#define RESTORE_SYMBOL_VERSION RESTORE_SYMBOL_BASE_VERSION //" (Debug version compiled " __DATE__ " " __TIME__ ")"
#else
#define RESTORE_SYMBOL_VERSION RESTORE_SYMBOL_BASE_VERSION
#endif

//#define RS_OPT_DISABLE_OC_DETECT 1
//#define RS_OPT_VERSION 2
//#define RS_OPT_REPLACE_RESTRICT 3

#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

void restore_symbol(NSString * inpath, NSString *outpath, NSString* outputObjcSymbolPath, NSString *jsonPath, bool oc_detect_enable, bool replace_restrict);

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
    bool replace_restrict = false;
    bool scanObjcSymbols = true;

    NSString *inpath = nil;
    NSString *outpath = nil;
    NSString *jsonPath = nil;
    NSString *outputObjcSymbolPath = nil;
    
    BOOL shouldPrintVersion = NO;
    BOOL onlyPrintHelp = NO;
    
    int longOptionChar;

    struct option longopts[] = {
        { "help",                       no_argument,       NULL, 'h' },
        { "version",                    no_argument,       NULL, 'v' },
        { "replace-restrict",           no_argument,       NULL, 'r' },
        { "export-objc-symbols",        required_argument, NULL, 'e' },
        { "json",                       required_argument, NULL, 'j' },
        { "output",                     required_argument, NULL, 'o' },
//        { "scan-objc-symbols",          optional_argument, NULL, 's' },
        { "scan-objc-symbols",          required_argument, NULL, 's' },

        { NULL,                      0,                 NULL, 0 },
    };

    if (argc == 1) {
        print_usage();
        exit(0);
    }

//    while ( (longOptionChar = getopt_long(argc, argv, "e:j:o:s::hv", longopts, NULL)) != -1) {
    while ( (longOptionChar = getopt_long(argc, argv, "e:j:o:s:hv", longopts, NULL)) != -1) {
//        printf("longOptionChar=%c\n", longOptionChar);
        switch (longOptionChar) {
            case 'h':
                onlyPrintHelp = YES;
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
//                // option with optional argument
////                if (optarg == NULL) {
//                if (OPTIONAL_ARGUMENT_IS_PRESENT) {
//                    // Handle is present
                    if (strcmp(optarg, "true") == 0) {
                        scanObjcSymbols = true;
                    } else if (strcmp(optarg, "false") == 0) {
                        scanObjcSymbols = false;
                    } else {
                        printf("Invalid value %s for --scan-objc-symbols\n", optarg);
                        onlyPrintHelp = true;
                    }
//                } else {
//                    // Handle is not present
//
//                    // default value is true
//                    scanObjcSymbols = true;
//                }
                break;
            case 'r':
                replace_restrict = true;
                break;
            default:
                break;
        }
    }
    
    if (onlyPrintHelp) {
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

//    restore_symbol(inpath, outpath, outputObjcSymbolPath, jsonPath, oc_detect_enable, replace_restrict);
    restore_symbol(inpath, outpath, outputObjcSymbolPath, jsonPath, scanObjcSymbols, replace_restrict);
    
}
