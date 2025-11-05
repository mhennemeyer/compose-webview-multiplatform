#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

#ifdef __cplusplus
extern "C" {
#endif

OSStatus KCAddGenericPassword(NSString *service,
                              NSString *account,
                              NSData *valueData,
                              LAContext * _Nullable context,
                              SecAccessControlRef _Nullable accessControl,
                              NSString * _Nullable operationPrompt);

OSStatus KCUpdateGenericPassword(NSString *service,
                                 NSString *account,
                                 NSData *valueData,
                                 LAContext * _Nullable context,
                                 NSString * _Nullable operationPrompt);

NSData * _Nullable KCCopyGenericPassword(NSString *service,
                               NSString *account,
                               LAContext * _Nullable context,
                               NSString * _Nullable operationPrompt,
                               OSStatus * _Nullable outStatus);

OSStatus KCDeleteGenericPassword(NSString *service,
                                 NSString *account);

#ifdef __cplusplus
}
#endif
