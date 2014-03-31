#import "ViewController.h"
#import "AESCrypt.h"
#import "NSString+Base64.h"
#import <CommonCrypto/CommonDigest.h>
@interface ViewController (){
    NSString *resultString;
}

- (NSString *)getMd5_32Bit_String:(NSString *)srcString;
- (NSString *)getMd5_16Bit_String:(NSString *)srcString;
@end

@implementation ViewController
@synthesize entryptTypeLabel;

@synthesize introLabel1;
@synthesize introLabel2;
@synthesize introLabel3;
@synthesize introLabel4;
@synthesize resultLabel1;
@synthesize resultLabel2;
@synthesize resultLabel3;
@synthesize resultLabel4;

@synthesize srcStringTextField;

- (void)viewDidLoad
{
    [super viewDidLoad];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}



- (IBAction)commonMd5BtnPressed:(id)sender {
    [entryptTypeLabel setText:@"常规md5加密"];
    
    [introLabel1 setText:@"32位小写"];
    [resultLabel1 setText:[self getMd5_32Bit_String:srcStringTextField.text]];
    
    //只需将得到的加密字串转化成大写即可
    [introLabel2 setText:@"32位大写"];
    [resultLabel2 setText:[[self getMd5_32Bit_String:srcStringTextField.text] uppercaseString]];
    
    [introLabel3 setText:@"16位小写"];
    [resultLabel3 setText:[self getMd5_16Bit_String:srcStringTextField.text]];
    
    [introLabel4 setText:@"16位大写"];
    [resultLabel4 setText:[[self getMd5_16Bit_String:srcStringTextField.text] uppercaseString]];
    
    
    
    NSString* message =@"欢迎光临JerryVon的博客";
     NSData* mData = [message dataUsingEncoding:NSUTF8StringEncoding];
    
    NSString *base64EncodedString = [NSString base64StringFromData:mData length:[mData length]];
    NSLog(@"%@",base64EncodedString);
//    NSLog(@"%@",[NSString base64StringFromData:mData length:mData.length] );
    // NSString *password = @"1234";
    
    // Encrypting
    
    // NSString *encryptedData = [AESCrypt encrypt:message password:password];
    //NSLog(@"aes encrypt:%@",encryptedData);
    // Decrypting
    
    //NSString *con = [AESCrypt decrypt:@"2fbwW9+8vPId2/foafZq6Q==" password:password];
    //NSLog(@"aes descrypt:%@",con);
    
}

- (IBAction)secondaryMd5BtnPressed:(id)sender {
    //实际上就是做两次常规转化
    [entryptTypeLabel setText:@"二次md5加密"];
    
    [introLabel1 setText:@"32位小写"];
    [resultLabel1 setText:[self getMd5_32Bit_String:[self getMd5_32Bit_String:srcStringTextField.text]]];
    
    //只需将得到的加密字串转化成大写即可
    [introLabel2 setText:@"32位大写"];
    [resultLabel2 setText:[[self getMd5_32Bit_String:[[self getMd5_32Bit_String:srcStringTextField.text] uppercaseString]]uppercaseString]];
    
    [introLabel3 setText:@"16位小写"];
    [resultLabel3 setText:[self getMd5_16Bit_String:[self getMd5_16Bit_String:srcStringTextField.text]]];
    
    [introLabel4 setText:@"16位大写"];
    [resultLabel4 setText:[[self getMd5_16Bit_String:[[self getMd5_16Bit_String:srcStringTextField.text] uppercaseString]] uppercaseString]];
}

//sha加密
- (IBAction)shaBtnPressed:(id)sender{
    [entryptTypeLabel setText:@"sha安全哈希加密"];
    
    [introLabel1 setText:@"sha1加密"];
    [resultLabel1 setText:[self getSha1String:srcStringTextField.text]];
    
    [introLabel2 setText:@"sha256加密"];
    [resultLabel2 setText:[self getSha256String:srcStringTextField.text]];
    
    [introLabel3 setText:@"sha384加密"];
    [resultLabel3 setText:[self getSha384String:srcStringTextField.text]];
    
    [introLabel4 setText:@"sha512加密"];
    [resultLabel4 setText:[self getSha512String:srcStringTextField.text]];
    NSLog(@"sha1加密:%@",resultLabel1.text);
    NSLog(@"sha256加密:%@",resultLabel2.text);
    NSLog(@"sha384加密:%@",resultLabel3.text);
    NSLog(@"sha512加密:%@",resultLabel4.text);
}

- (IBAction)bgTap:(id)sender {
    [self.srcStringTextField resignFirstResponder];
}

//16位MD5加密方式
- (NSString *)getMd5_16Bit_String:(NSString *)srcString{
    //提取32位MD5散列的中间16位
    NSString *md5_32Bit_String=[self getMd5_32Bit_String:srcString];
    NSString *result = [[md5_32Bit_String substringToIndex:24] substringFromIndex:8];//即9～25位
    
    return result;
}


//32位MD5加密方式
- (NSString *)getMd5_32Bit_String:(NSString *)srcString{
    const char *cStr = [srcString UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, strlen(cStr), digest );
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    
    return result;
}

//sha1加密方式
- (NSString *)getSha1String:(NSString *)srcString{
    //这个好像不对，无法和JAVA端成对
    //    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    //NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    // uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    // CC_SHA1(data.bytes, data.length, digest);
    const char *cstr = [srcString UTF8String];
    //使用对应的CC_SHA1,CC_SHA256,CC_SHA384,CC_SHA512的长度分别是20,32,48,64
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    //使用对应的CC_SHA256,CC_SHA384,CC_SHA512
    CC_SHA1(cstr,  strlen(cstr), digest);
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

//sha256加密方式
- (NSString *)getSha256String:(NSString *)srcString {
    //    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    //    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    //    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    // CC_SHA1(data.bytes, data.length, digest);
    const char *cstr = [srcString UTF8String];
    
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cstr,  strlen(cstr), digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
}

//sha384加密方式
- (NSString *)getSha384String:(NSString *)srcString {
//    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
//    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
//    uint8_t digest[CC_SHA384_DIGEST_LENGTH];
//    CC_SHA1(data.bytes, data.length, digest);
    const char *cstr = [srcString UTF8String];
    
    unsigned char digest[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384(cstr,  strlen(cstr), digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA384_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA384_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
}

//sha512加密方式
- (NSString*) getSha512String:(NSString*)srcString {
//    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
//    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
//    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
//    CC_SHA512(data.bytes, data.length, digest);
    const char *cstr = [srcString UTF8String];
    
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(cstr,  strlen(cstr), digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    return result;
}




@end