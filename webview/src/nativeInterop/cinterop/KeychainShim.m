#import "KeychainShim.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

OSStatus KCAddGenericPassword(NSString *service,
                              NSString *account,
                              NSData *valueData,
                              LAContext * _Nullable context,
                              SecAccessControlRef _Nullable accessControl,
                              NSString * _Nullable operationPrompt) {
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrService] = service;
    query[(__bridge id)kSecAttrAccount] = account;
    if (accessControl) {
        query[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControl;
    }
    if (context) {
        query[(__bridge id)kSecUseAuthenticationContext] = context;
    }
    if (operationPrompt) {
        query[(__bridge id)kSecUseOperationPrompt] = operationPrompt;
    }
    query[(__bridge id)kSecValueData] = valueData;
    return SecItemAdd((__bridge CFDictionaryRef)query, NULL);
}

OSStatus KCUpdateGenericPassword(NSString *service,
                                 NSString *account,
                                 NSData *valueData,
                                 LAContext * _Nullable context,
                                 NSString * _Nullable operationPrompt) {
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrService] = service;
    query[(__bridge id)kSecAttrAccount] = account;
    if (context) {
        query[(__bridge id)kSecUseAuthenticationContext] = context;
    }
    if (operationPrompt) {
        query[(__bridge id)kSecUseOperationPrompt] = operationPrompt;
    }

    NSDictionary *attrs = @{ (__bridge id)kSecValueData: valueData };
    return SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
}

OSStatus KCCopyGenericPassword(NSString *service,
                               NSString *account,
                               LAContext * _Nullable context,
                               NSString * _Nullable operationPrompt,
                               NSData * __autoreleasing _Nullable * _Nullable outData) {
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    query[(__bridge id)kSecAttrService] = service;
    query[(__bridge id)kSecAttrAccount] = account;
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    if (context) {
        query[(__bridge id)kSecUseAuthenticationContext] = context;
    }
    if (operationPrompt) {
        query[(__bridge id)kSecUseOperationPrompt] = operationPrompt;
    }

    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (outData) {
        if (st == errSecSuccess && result) {
            *outData = (__bridge_transfer NSData *)result;
        } else {
            *outData = nil;
            if (result) CFRelease(result);
        }
    } else if (result) {
        CFRelease(result);
    }
    return st;
}

OSStatus KCDeleteGenericPassword(NSString *service,
                                 NSString *account) {
    NSDictionary *query = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                             (__bridge id)kSecAttrService: service,
                             (__bridge id)kSecAttrAccount: account };
    return SecItemDelete((__bridge CFDictionaryRef)query);
}
