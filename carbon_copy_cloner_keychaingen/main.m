//
//  main.m
//  carbon_copy_cloner_keychaingen
//
//  Created by reverser on 25/10/2018.
//  Copyright © 2018 Put.as. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <sys/sysctl.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        printf("                                    _\n"
               "  /\\ /\\___ _   _  __ _  ___ _ __   / \\\n"
               " / //_/ _ \\ | | |/ _` |/ _ \\ '_ \\ /  /\n"
               "/ __ \\  __/ |_| | (_| |  __/ | | /\\_/\n"
               "\\/  \\/\\___|\\__, |\\__, |\\___|_| |_\\/\n"
               "           |___/ |___/\n"
               "    Carbon Copy Cloner 5 Keychain\n\n"
               "(c) fG! - 2018 - https://reverse.put.as\n\n");

        /* both IOPlatformUUID and IOPlatformSerialNumber are used so retrieve them now */
        io_registry_entry_t io_registry = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
        CFStringRef platformUUID = IORegistryEntryCreateCFProperty(io_registry, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        const char* platformUUID_str = CFStringGetCStringPtr(platformUUID,kCFStringEncodingMacRoman);
        printf("Your IOPlatformUUID is: %s\n", platformUUID_str);

        CFStringRef serialNumber;
        serialNumber = IORegistryEntryCreateCFProperty(io_registry, CFSTR("IOPlatformSerialNumber"), kCFAllocatorDefault, 0);
        const char* platformSerial_str = CFStringGetCStringPtr(serialNumber,kCFStringEncodingMacRoman);
        printf("Your IOPlatformSerialNumber is: %s\n", platformSerial_str);

        /* the dashes are removed from the IOPlatformUUID */
        NSString *cleanPlatformUUID = [(NSString*)CFBridgingRelease(platformUUID) stringByReplacingOccurrencesOfString:@"-" withString:@""];
        /* this is the final password buffer - first it is filled with the clean IOPlatformUUID */
        char *password = calloc(0x41, sizeof(char));
        snprintf(password, 0x41, "%s%s", [cleanPlatformUUID UTF8String], [cleanPlatformUUID UTF8String]);
        printf("Initial password buffer: %s\n", password);

        /* two hardware sysctls are retrieved - the model name and the number of cpus */
        int mib[2] = {0};
        mib[0] = CTL_HW;
        mib[1] = HW_MODEL;
        size_t length = 0;
        /* first we query what is the size of the model name string */
        if (sysctl(mib, 2, NULL, &length, NULL, 0) != 0)
        {
            fprintf(stderr, "Failed to execute sysctl\n");
            return EXIT_FAILURE;
        }
        /* now we can allocate memory and pass it to sysctl to get the model name string */
        char *hw_model = malloc(length);
        if (sysctl(mib, 2, hw_model, &length, NULL, 0) != 0)
        {
            fprintf(stderr, "Failed to execute sysctl\n");
            return EXIT_FAILURE;
        }
        printf("Model name: %s\n", hw_model);
        /* the number of cpus we don't need to allocate memory s*/
        int ncpu = 0;
        mib[1] = HW_NCPU;
        if (sysctl(mib, 2, &ncpu, &length, NULL, 0) != 0)
        {
            fprintf(stderr, "Failed to execute sysctl\n");
            return EXIT_FAILURE;
        }
        printf("Number of CPUs: %d\n", ncpu);
        
        /* a second buffer is allocated to hold the model and serial number */
        char *temp_buffer = calloc(0x80, sizeof(char));
        snprintf(temp_buffer, 0x80, "%s%s", hw_model, platformSerial_str);
        
        /* length of the password buffer is the upper bound */
        size_t password_len = strlen(password);
        /* the buffer with model and serial number is iterated in a circular way */
        size_t temp_buffer_index = 0;

        /*
         * Addresses from /Library/PrivilegedHelperTools/com.bombich.ccchelper (Version 5.1.4 (5482))
         * SHA256(com.bombich.ccchelper)= e840e18ee498c6fd989c397b1f8298d5e983671ab3bb7123652744f150c91419
         */
        for (size_t x = 0; x < password_len; x++)
        {
            /*
             10011655A  mov     r12b, [r13+rbx+0]
             (...)
             100116564  mov     rax, rsi
             100116567  cqo
             100116569  idiv    rdi
             10011656C  movsx   eax, r12b
             100116570  sub     eax, edx
             100116572  mov     edx, 0
             100116577  cmovz   edx, edi
             */
            int a = x % ncpu;
            int b = temp_buffer[temp_buffer_index];
            int c = 0;
            if (a == b)
            {
                c = ncpu;
            }
            b -= a;
            /*
             10011655F  movsx   ecx, byte ptr [r15+rsi]
             (...)
             10011657A  add     eax, ecx
             10011657C  add     eax, edx
            */
            int d = password[x] + b + c;
            /*
             10011657E  cdqe
             100116580  imul    rcx, rax, 0FFFFFFFF82082083h
             100116587  shr     rcx, 20h
             */
            int64_t e = (int64_t)(d * 0x0FFFFFFFF82082083) >> 0x20;
            /*
             10011658B  add     ecx, eax
             */
            int32_t f = (int32_t)(e + d);
            /*
             10011658D  mov     edx, ecx
             10011658F  shr     edx, 1Fh
             */
            int32_t g = f >> 0x1F;
            /*
             100116592  sar     ecx, 6
             */
            int32_t h = f / 64;
            /*
             100116595  add     ecx, edx
             100116597  imul    ecx, 7Eh
             */
            unsigned int i = (g + h) * 0x7E;
            /*
             10011659A  mov     edx, eax
             10011659C  sub     edx, ecx
             */
            int32_t j = d - i;
            /*
             10011659E  cmp     eax, 7Eh
             1001165A1  cmovle  edx, eax
             1001165A4  lea     eax, [rdx+20h]
             */
            int32_t k = 0;
            if (d <= 0x7E)
            {
                k = d;
            }
            else
            {
                k = j + 0x20;
            }
            /*
             1001165A7  cmp     edx, r8d
             1001165AA  cmovge  eax, edx
             */
            if (j >= 0x20)
            {
                k = j;
            }
            /* just a debugging message to compare steps */
//            printf("a:0x%x b:0x%x c: 0x%x d:0x%x e: 0x%llx f: 0x%x g:0x%x h:0x%x j:0x%x final:%c 0x%x\n", a, b, c, d, e, f, g, h, j, k, k);
            /*
             1001165B1  mov     rax, rbx
             1001165B4  inc     rax
             1001165B7  cmp     rax, r9
             1001165BA  mov     ebx, 0
             1001165BF  cmovnz  rbx, rax
             */
            if (++temp_buffer_index == strlen(temp_buffer))
            {
                temp_buffer_index = 0;
            }
            
            /* replace the generated character in the original password buffer */
            password[x] = (char)k;
        }
        printf("\nYour local Carbon Copy Cloner keychain password is: %s\n", password);
        printf("\nYou can find the keychain at \"/Library/Application Support/com.bombich.ccc/CCC-global.keychain\"\n");
        printf("Admin privileges are required to access that file.\n");
    }
    return 0;
}
