//
//  ViewController.m
//  Integration BCA
//
//  Created by Ravi Tej on 5/11/18.
//  Copyright © 2018 Ravi Tej. All rights reserved.
//

#import "ViewController.h"

static NSString *errorDomain = @"MSIWriter";


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

+ (NSDictionary *)sharedKeychainQueryFromQuery:(NSDictionary *)query andSharedAccessGroup:(NSString *)sharedAccessGroup {
    NSMutableDictionary *mutableQuery = [query mutableCopy];
    // it is only safe to use the shared keychain on a device
#if !TARGET_IPHONE_SIMULATOR
    [mutableQuery setObject:sharedAccessGroup forKey:(NSString *)kSecAttrAccessGroup];
#endif
    return mutableQuery;
}


+ (BOOL) storeKey:(NSString *) username andSecureString:(NSString *) password andServiceName:(NSString *) serviceName andSharedAccessGroup:(NSString *)sharedAccessGroup updateExisting:(BOOL) updateExisting isSharedKeychain:(BOOL)isSharedKeychain error:(NSError **) error

{
    if (!username || !password || !serviceName)
        
    {
        if (error != nil)
        {
            *error = [NSError errorWithDomain: errorDomain code: -2000 userInfo: nil];
        }
        return NO;
    }
    
    // See if we already have a password entered for these credentials.
    
    NSError *getError = nil;
    NSString *existingPassword = [ViewController getSecureStringForKey:username andServiceName:serviceName andSharedAccessGroup:sharedAccessGroup isSharedKeychain:TRUE clearSecret:(BOOL)FALSE error:&getError];
    
    if ([getError code] == -1999)
    {
        NSLog(@"Existing key without password?!?");
        // There is an existing entry without a password properly stored (possibly as a result of the previous incorrect version of this code.
        
        // Delete the existing item before moving on entering a correct one.
        getError = nil;
        
        [ViewController deleteItemForKey:username andServiceName:serviceName andSharedAccessGroup:sharedAccessGroup error:&getError];
        
        if ([getError code] != noErr)
        {
            if (error != nil)
            {
                *error = getError;
            }
            return NO;
        }
    }
    else if ([getError code] != noErr)
    {
        NSLog(@"Error when getting existing password: %@", getError);
        if (error != nil)
        {
            *error = getError;
        }
        return NO;
    }
    if (error != nil)
    {
        *error = nil;
    }
    
    OSStatus status = noErr;
    
    if (existingPassword)
    {
        NSLog(@"ExistingPassword");
        // We have an existing, properly entered item with a password.
        // Update the existing item.
        
        if (![existingPassword isEqualToString:password] && updateExisting)
        {
            //Only update if we're allowed to update existing.  If not, simply do nothing.
            
            NSArray *keys = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *)  kSecAttrAccessible, kSecClass,kSecAttrService,kSecAttrLabel,kSecAttrAccount,nil];
            
            NSArray *objects = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *) kSecAttrAccessibleWhenUnlocked, kSecClassGenericPassword,serviceName,serviceName,username,nil];
            
            NSDictionary *query = [[NSDictionary alloc] initWithObjects: objects forKeys: keys];
            if (isSharedKeychain) {
                query = [ViewController sharedKeychainQueryFromQuery:query andSharedAccessGroup: sharedAccessGroup];
            }
            NSLog(@"About to SecItemUpdate");
            status = SecItemUpdate((__bridge_retained CFDictionaryRef) query, (__bridge_retained CFDictionaryRef) [NSDictionary dictionaryWithObject: [password dataUsingEncoding: NSUTF8StringEncoding] forKey: (__bridge_transfer NSString *) kSecValueData]);
            
            if (status != noErr) {
                NSString *message = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
                NSLog(@"Error in SecItemUpdate: %@", message);
            }

        } else {
            NSLog(@"not updating existing password");
        }
    }
    else
    {
        // No existing entry (or an existing, improperly entered, and therefore now
        
        // deleted, entry).  Create a new entry.
        
        
        NSArray *keys = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *) kSecAttrAccessible, kSecClass,kSecAttrService,kSecAttrLabel,kSecAttrAccount,kSecValueData,nil];
        
        NSArray *objects = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *) kSecAttrAccessibleWhenUnlocked, kSecClassGenericPassword,serviceName,serviceName,username,[password dataUsingEncoding: NSUTF8StringEncoding],nil];
        
        NSDictionary *query = [[NSDictionary alloc] initWithObjects: objects forKeys: keys];
        if (isSharedKeychain) {
            query = [ViewController sharedKeychainQueryFromQuery:query andSharedAccessGroup: sharedAccessGroup];
        }
        NSLog(@"About to SecItemAdd");
        status = SecItemAdd((__bridge_retained CFDictionaryRef) query, NULL);
        
        if (status != noErr) {
            NSString *message = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
            NSLog(@"Error in SecItemAdd: %@", message);
        }

    }
    if (error != nil && status != noErr)
    {
        // Something went wrong with adding the new item. Return the Keychain error code.
        *error = [NSError errorWithDomain: errorDomain code: status userInfo: nil];
        return NO;
    }
    return YES;
}

+ (BOOL) deleteItemForKey:(NSString *) username andServiceName:(NSString *) serviceName andSharedAccessGroup:(NSString *)sharedAccessGroup error:(NSError **) error
{
    if (!username || !serviceName || !sharedAccessGroup)
    {
        if (error != nil)
        {
            *error = [NSError errorWithDomain: errorDomain code: -2000 userInfo: nil];
        }
        return NO;
    }
    if (error != nil)
    {
        *error = nil;
    }
    NSArray *keys = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *) kSecClass, kSecAttrAccount, kSecAttrService, kSecReturnAttributes, nil];
    NSArray *objects = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *) kSecClassGenericPassword, username, serviceName, kCFBooleanTrue, nil];
    NSDictionary *query = [[NSDictionary alloc] initWithObjects: objects forKeys: keys];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef) query);
    
    if (status != noErr) {
        NSString *message = (__bridge_transfer NSString *)SecCopyErrorMessageString(status, NULL);
        NSLog(@"Error in SecItemDelete: %@", message);
    }
    
    if (error != nil && status != noErr)
    {
        *error = [NSError errorWithDomain: errorDomain code: status userInfo: nil];
        return NO;
    }
    return YES;
}

+ (NSString *) getSecureStringForKey:(NSString *) username andServiceName:(NSString *) serviceName andSharedAccessGroup:(NSString *)sharedAccessGroup isSharedKeychain:(BOOL)isSharedKeychain clearSecret:(BOOL)clearSecret error:(NSError **) error {
    
    if (!username || !serviceName) {
        if (error != nil) {
            *error = [NSError errorWithDomain: errorDomain code: -2000 userInfo: nil];
        }
        return nil;
    }
    
    if (error != nil) {
        *error = nil;
    }
    // Set up a query dictionary with the base query attributes: item type (generic), username, and service
    NSArray *keys = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *) kSecClass, kSecAttrAccount, kSecAttrService, nil];
    NSArray *objects = [[NSArray alloc] initWithObjects: (__bridge_transfer NSString *) kSecClassGenericPassword, username, serviceName, nil];
    NSMutableDictionary *query = [[NSMutableDictionary alloc] initWithObjects: objects forKeys: keys];
    if (isSharedKeychain) {
        query = [[ViewController sharedKeychainQueryFromQuery:query andSharedAccessGroup:sharedAccessGroup] mutableCopy];
    }
    // First do a query for attributes, in case we already have a Keychain item with no password data set.
    // One likely way such an incorrect item could have come about is due to the previous (incorrect)
    // version of this code (which set the password as a generic attribute instead of password data).
    NSMutableDictionary *attributeQuery = [query mutableCopy];
    [attributeQuery setObject: (id) kCFBooleanTrue forKey:(__bridge_transfer id) kSecReturnAttributes];
    CFTypeRef attrResult = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) attributeQuery, &attrResult);
    //NSDictionary *attributeResult = (__bridge_transfer NSDictionary *)attrResult;
    if (status != noErr) {
        // No existing item found--simply return nil for the password
        if (error != nil && status != errSecItemNotFound) {
            //Only return an error if a real exception happened--not simply for "not found."
            *error = [NSError errorWithDomain: errorDomain code: status userInfo: nil];
        }
        return nil;
    }
    
    // We have an existing item, now query for the password data associated with it.
    NSMutableDictionary *passwordQuery = [query mutableCopy];
    [passwordQuery setObject: (id) kCFBooleanTrue forKey: (__bridge_transfer id) kSecReturnData];
    CFTypeRef resData = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef) passwordQuery, (CFTypeRef *) &resData);
    NSData *resultData = (__bridge_transfer NSData *)resData;
    if (status != noErr) {
        if (status == errSecItemNotFound) {
            // We found attributes for the item previously, but no password now, so return a special error.
            // Users of this API will probably want to detect this error and prompt the user to
            // re-enter their credentials.  When you attempt to store the re-entered credentials
            // using storeUsername:andPassword:forServiceName:updateExisting:error
            // the old, incorrect entry will be deleted and a new one with a properly encrypted
            // password will be added.
            
            if (error != nil) {
                *error = [NSError errorWithDomain: errorDomain code: -1999 userInfo: nil];
            }
        }
        else {
            // Something else went wrong. Simply return the normal Keychain API error code.
            if (error != nil) {
                *error = [NSError errorWithDomain: errorDomain code: status userInfo: nil];
            }
        }
        return nil;
    }
    NSString *password = nil;
    if (resultData) {
        password = [[NSString alloc] initWithData: resultData encoding: NSUTF8StringEncoding];
    }
    else {
        // There is an existing item, but we weren't able to get password data for it for some reason,
        // Possibly as a result of an item being incorrectly entered by the previous code.
        // Set the -1999 error so the code above us can prompt the user again.
        
        if (error != nil) {
            *error = [NSError errorWithDomain: errorDomain code: -1999 userInfo: nil];
        }
    }
    
    /*
    if (clearSecret) {
        [CDVSharedSecret storeKey:username andSecureString:@"" andServiceName:serviceName andSharedAccessGroup:@"2526YS86J3.com.movencorp.b2bpartner.bca" updateExisting:TRUE isSharedKeychain:(BOOL)TRUE error:error];
    }
    */
    
    return password;
}

- (IBAction)showAlert:(UIButton *)sender {
    NSLog(@"Button Pressed");
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    
    NSDate *currentDate = [NSDate date];
    NSString *token = [formatter stringFromDate:currentDate];
    
    NSError *theError = nil;
    [ViewController storeKey:@"MovenToken" andSecureString:token andServiceName:@"MovenWellnessSettings" andSharedAccessGroup:@"2526YS86J3.com.moven.b2bpartner.bca" updateExisting:TRUE isSharedKeychain:(BOOL)TRUE error:&theError];
    
    NSString *message = theError == nil ? [NSString stringWithFormat:@"Token '%@' Saved", token] : [NSString stringWithFormat:@"Error: %@", theError];
    
    NSLog(@"%@", message);
    UIAlertController * alert = [UIAlertController alertControllerWithTitle:@"Alert" message:message preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction * action = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {}];
    
    [alert addAction:action];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
