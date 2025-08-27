#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <applescript_file> <handler_name> [args...]\n", argv[0]);
        return 1;
    }
    
    // Build argument vector for osascript - secure approach avoiding shell injection
    // osascript <applescript_file> <handler_name> [args...]
    int arg_count = argc; // osascript + all args except argv[0]
    char **cmd_argv = malloc((arg_count + 1) * sizeof(char *)); // +1 for NULL terminator
    if (!cmd_argv) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    
    cmd_argv[0] = "osascript";
    for (int i = 1; i < argc; i++) {
        cmd_argv[i] = argv[i]; // Direct argument passing - no shell interpretation
    }
    cmd_argv[arg_count] = NULL;
    
    // Fork and execute to avoid shell injection vulnerabilities
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - execute osascript directly
        execvp("osascript", cmd_argv);
        // If execvp returns, there was an error
        perror("execvp failed");
        free(cmd_argv);
        exit(1);
    } else if (pid > 0) {
        // Parent process - wait for child and get exit status
        int status;
        waitpid(pid, &status, 0);
        free(cmd_argv);
        return WEXITSTATUS(status);
    } else {
        // Fork failed
        perror("fork failed");
        free(cmd_argv);
        return 1;
    }
}
