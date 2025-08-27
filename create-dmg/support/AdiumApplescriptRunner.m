#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc < 3) {
            NSLog(@"Usage: %s <script_file> <function_name> [arguments...]", argv[0]);
            return 1;
        }
        
        NSString *scriptPath = [NSString stringWithUTF8String:argv[1]];
        NSString *functionName = [NSString stringWithUTF8String:argv[2]];
        
        // Read the AppleScript file
        NSError *error = nil;
        NSString *scriptSource = [NSString stringWithContentsOfFile:scriptPath 
                                                            encoding:NSUTF8StringEncoding 
                                                               error:&error];
        if (error) {
            NSLog(@"Error reading script file: %@", error.localizedDescription);
            return 1;
        }
        
        // Create AppleScript object
        NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:scriptSource];
        if (!appleScript) {
            NSLog(@"Error creating AppleScript object");
            return 1;
        }
        
        // Compile the script
        NSDictionary *errorInfo = nil;
        if (![appleScript compileAndReturnError:&errorInfo]) {
            NSLog(@"Error compiling script: %@", errorInfo);
            return 1;
        }
        
        // Prepare arguments for the function call
        NSMutableArray *arguments = [NSMutableArray array];
        for (int i = 3; i < argc; i++) {
            [arguments addObject:[NSString stringWithUTF8String:argv[i]]];
        }
        
        // Create AppleScript event to call the function
        NSAppleEventDescriptor *functionDesc = [NSAppleEventDescriptor descriptorWithString:functionName];
        NSAppleEventDescriptor *argumentsDesc = [NSAppleEventDescriptor listDescriptor];
        
        for (int i = 0; i < arguments.count; i++) {
            NSString *arg = [arguments objectAtIndex:i];
            [argumentsDesc insertDescriptor:[NSAppleEventDescriptor descriptorWithString:arg] 
                                    atIndex:i + 1];
        }
        
        // Execute the AppleScript function
        NSAppleEventDescriptor *result = [appleScript executeAndReturnError:&errorInfo];
        if (errorInfo) {
            NSLog(@"Error executing script: %@", errorInfo);
            return 1;
        }
        
        if (result) {
            NSLog(@"Script executed successfully");
        }
        
        return 0;
    }
}
