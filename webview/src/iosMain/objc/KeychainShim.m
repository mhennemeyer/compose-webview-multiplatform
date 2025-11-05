#import "KeychainShim.h"

static inline NSString *KCStr(const char *cstr) {
    if (cstr == NULL) return nil;
    return [NSString stringWithUTF8String:cstr];
}

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

NSData * KCCopyGenericPassword(NSString *service,
                               NSString *account,
                               LAContext * _Nullable context,
                               NSString * _Nullable operationPrompt,
                               OSStatus * _Nullable outStatus) {
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
    NSData *data = nil;
    if (st == errSecSuccess && result) {
        data = (__bridge_transfer NSData *)result;
    } else if (result) {
        CFRelease(result);
    }
    if (outStatus) *outStatus = st;
    return data;
}

OSStatus KCDeleteGenericPassword(const char *service,
                                 const char *account) {
    NSDictionary *query = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                             (__bridge id)kSecAttrService: KCStr(service),
                             (__bridge id)kSecAttrAccount: KCStr(account) };
    return SecItemDelete((__bridge CFDictionaryRef)query);
}
