#import <Foundation/Foundation.h>
#import <OSAKit/OSAKit.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s <script_file> <function_name>\n", argv[0]);
            return 1;
        }
        
        NSString *scriptPath = [NSString stringWithUTF8String:argv[1]];
        NSString *functionName = [NSString stringWithUTF8String:argv[2]];
        
        // Read the AppleScript file
        NSError *error = nil;
        NSString *scriptSource = [NSString stringWithContentsOfFile:scriptPath 
                                                           encoding:NSUTF8StringEncoding 
                                                              error:&error];
        if (!scriptSource) {
            fprintf(stderr, "Error reading script file: %s\n", [[error localizedDescription] UTF8String]);
            return 1;
        }
        
        // Create and compile the AppleScript
        NSDictionary *errorInfo = nil;
        OSAScript *script = [[OSAScript alloc] initWithSource:scriptSource language:[OSALanguage languageForName:@"AppleScript"]];
        if (![script compileAndReturnError:&errorInfo]) {
            fprintf(stderr, "Error compiling script: %s\n", [[errorInfo description] UTF8String]);
            return 1;
        }
        
        // Execute the script
        NSAppleEventDescriptor *result = [script executeAndReturnError:&errorInfo];
        if (!result) {
            fprintf(stderr, "Error executing script: %s\n", [[errorInfo description] UTF8String]);
            return 1;
        }
        
        return 0;
    }
}
