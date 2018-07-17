#import <Foundation/Foundation.h>
#import <substrate.h>

static NSArray *NotAllowedPathPrefixes;

static BOOL allowAccess(NSString *filename) {
    if ([filename hasPrefix:@"/private"]) {
        filename = [filename substringFromIndex:@"/private".length];
    }
    if (filename.length == 0) {
        return YES;
    }
    for (NSString *prefix in NotAllowedPathPrefixes) {
        if ([filename hasPrefix:prefix]) {
            return NO;
        }
    }
    return YES;
}

%group pwnDetection
int stat (const char *filename, struct stat *result);
%hookf(int *, stat, const char *filename, struct stat *result) {
    if (!allowAccess([NSString stringWithUTF8String:filename])) {
        filename = "";
    }
    return %orig;
}

int lstat (const char *filename, struct stat *result);
%hookf(int *, lstat, const char *filename, struct stat *result) {
    if (!allowAccess([NSString stringWithUTF8String:filename])) {
        filename = "";
    }
    return %orig;
}

FILE *fopen(const char *filename, const char *mode);
%hookf(FILE **, fopen, const char *filename, const char *mode) {
    if (!allowAccess([NSString stringWithUTF8String:filename])) {
        filename = "";
    }
    return %orig;
}
%end

%ctor {
    @autoreleasepool {
        NotAllowedPathPrefixes = @[
            @"/bin",
            @"/usr/bin",
            @"/usr/sbin",
            @"/usr/libexec",
            @"/etc/passwd",
            @"/etc/ssh",
            @"/var/log",
            @"/var/tmp",
            @"/Applications",
            @"/Library/MobileSubstrate",
            @"/System/Library/LaunchDaemons"
        ];
        %init(pwnDetection);
    }
}