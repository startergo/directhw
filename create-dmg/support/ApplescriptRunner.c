#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <applescript_file> <handler_name> [args...]\n", argv[0]);
        return 1;
    }
    
    char *applescript_file = argv[1];
    char *handler_name = argv[2];
    
    // Build the osascript command
    char command[2048];
    snprintf(command, sizeof(command), "osascript \"%s\"", applescript_file);
    
    // Add handler name and any additional arguments
    for (int i = 3; i < argc; i++) {
        char arg_part[256];
        snprintf(arg_part, sizeof(arg_part), " \"%s\"", argv[i]);
        strncat(command, arg_part, sizeof(command) - strlen(command) - 1);
    }
    
    // Execute the command
    int result = system(command);
    return WEXITSTATUS(result);
}
