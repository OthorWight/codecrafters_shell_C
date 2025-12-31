/*
 * C Shell
 * * Features:
 * - Pipelining (|)
 * - Redirection (<, >, >>, 2>, 2>>)
 * - Quote handling ('', "")
 * - Tab completion (Files and Executables)
 * - History management (persistent via HISTFILE)
 * - Builtins (cd, pwd, echo, type, exit, history)
 * - Signal handling (Ctrl+C)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <dirent.h>

// Readline library
#include <readline/readline.h>
#include <readline/history.h>

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

#define MAX_ARGS 128
#define MAX_PIPELINE_SEGMENTS 32
#define PATH_BUF_SIZE 4096
#define SHELL_NAME "myshell"

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Dynamic Array for strings
typedef struct {
    char **elements;
    int count;
    int capacity;
} StringArray;

// Represents a single command in a pipeline (e.g., "grep foo input.txt")
typedef struct {
    char **args;            // parsed arguments
    int arg_count;
    
    char *input_file;       // <
    char *output_stdout;    // > or >>
    bool append_stdout;
    char *output_stderr;    // 2> or 2>>
    bool append_stderr;

    int builtin_idx;        // -1 if external
    pid_t pid;
    int exit_status;
} Command;

// Represents the entire line (e.g., "ls | grep foo")
typedef struct {
    Command segments[MAX_PIPELINE_SEGMENTS];
    int num_segments;
} Pipeline;

typedef int (*builtin_func_t)(int argc, char **argv);

typedef struct {
    const char *name;
    builtin_func_t handler;
} Builtin;

// ============================================================================
// PROTOTYPES
// ============================================================================

// Utils
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);
void free_str_array(char **array);

// String Array
void sa_init(StringArray *sa, int capacity);
void sa_add(StringArray *sa, char *str); // takes ownership
void sa_free(StringArray *sa);
void sa_sort_unique(StringArray *sa);

// Parser
char **tokenize_input(const char *input, int *count);
Pipeline *parse_pipeline(const char *line);
void free_pipeline(Pipeline *p);

// Execution
int execute_pipeline(Pipeline *p);
char *find_executable(const char *cmd);

// Builtins
int builtin_cd(int argc, char **argv);
int builtin_echo(int argc, char **argv);
int builtin_exit(int argc, char **argv);
int builtin_pwd(int argc, char **argv);
int builtin_type(int argc, char **argv);
int builtin_history(int argc, char **argv);

// Autocomplete & Signals
char **shell_completion(const char *text, int start, int end);
void setup_signals(void);
void cleanup_shell(void);

// Global Builtin Table
static const Builtin BUILTINS[] = {
    {"cd", builtin_cd},
    {"echo", builtin_echo},
    {"exit", builtin_exit},
    {"pwd", builtin_pwd},
    {"type", builtin_type},
    {"history", builtin_history},
    {NULL, NULL}
};

static StringArray completion_matches;
static int completion_idx;
static int last_history_sync = 0;

// ============================================================================
// UTILITIES
// ============================================================================

void *xmalloc(size_t size) {
    void *p = malloc(size);
    if (!p && size > 0) {
        fprintf(stderr, "Fatal: Out of memory\n");
        exit(EXIT_FAILURE);
    }
    return p;
}

void *xrealloc(void *ptr, size_t size) {
    void *p = realloc(ptr, size);
    if (!p && size > 0) {
        fprintf(stderr, "Fatal: Out of memory\n");
        exit(EXIT_FAILURE);
    }
    return p;
}

char *xstrdup(const char *s) {
    if (!s) return NULL;
    char *d = strdup(s);
    if (!d) {
        fprintf(stderr, "Fatal: Out of memory\n");
        exit(EXIT_FAILURE);
    }
    return d;
}

void free_str_array(char **array) {
    if (!array) return;
    for (int i = 0; array[i]; i++) {
        free(array[i]);
    }
    free(array);
}

// ============================================================================
// STRING ARRAY (Dynamic Array)
// ============================================================================

void sa_init(StringArray *sa, int capacity) {
    sa->capacity = (capacity > 0) ? capacity : 16;
    sa->count = 0;
    sa->elements = xmalloc(sa->capacity * sizeof(char*));
}

void sa_add(StringArray *sa, char *str) {
    if (sa->count >= sa->capacity) {
        sa->capacity *= 2;
        sa->elements = xrealloc(sa->elements, sa->capacity * sizeof(char*));
    }
    sa->elements[sa->count++] = str;
}

void sa_free(StringArray *sa) {
    for (int i = 0; i < sa->count; i++) {
        free(sa->elements[i]);
    }
    free(sa->elements);
    sa->elements = NULL;
    sa->count = 0;
}

int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

void sa_sort_unique(StringArray *sa) {
    if (sa->count <= 1) return;
    qsort(sa->elements, sa->count, sizeof(char*), cmp_str);

    int dest = 0;
    for (int src = 1; src < sa->count; src++) {
        if (strcmp(sa->elements[dest], sa->elements[src]) != 0) {
            dest++;
            sa->elements[dest] = sa->elements[src];
        } else {
            free(sa->elements[src]);
        }
    }
    sa->count = dest + 1;
}

// ============================================================================
// PARSER (Tokenization & Pipeline Construction)
// ============================================================================

// A robust tokenizer that handles 'single' and "double" quotes and backslashes
char **tokenize_input(const char *input, int *count) {
    *count = 0;
    if (!input) return NULL;

    int capacity = 16;
    char **tokens = xmalloc((capacity + 1) * sizeof(char*));
    char buf[4096]; // Temp buffer for current token
    int buf_idx = 0;
    const char *p = input;
    
    bool in_sq = false; // single quote
    bool in_dq = false; // double quote
    bool token_started = false;

    while (*p) {
        // Skip whitespace between tokens
        while (*p && isspace((unsigned char)*p) && !in_sq && !in_dq) p++;
        if (!*p) break;

        buf_idx = 0;
        token_started = true;
        
        while (*p) {
            char c = *p;
            if (in_sq) {
                if (c == '\'') { in_sq = false; }
                else { buf[buf_idx++] = c; }
            } else if (in_dq) {
                if (c == '"') { in_dq = false; }
                else if (c == '\\' && (p[1] == '"' || p[1] == '$' || p[1] == '\\')) {
                    p++; buf[buf_idx++] = *p; // Escape special chars inside double quotes
                } else { buf[buf_idx++] = c; }
            } else {
                if (isspace((unsigned char)c)) { break; }
                if (c == '|') {
                    // Pipe is a delimiter, but if we have accumulated a token, finish it first
                    if (buf_idx > 0) goto save_token; 
                    // If buffer empty, pipe is the token
                    buf[buf_idx++] = c; 
                    p++; 
                    goto save_token;
                }
                if (c == '\'' ) { in_sq = true; }
                else if (c == '"') { in_dq = true; }
                else if (c == '\\') { p++; if(*p) buf[buf_idx++] = *p; }
                else { buf[buf_idx++] = c; }
            }
            p++;
            if (buf_idx >= sizeof(buf) - 1) break; // Overflow protection
        }

    save_token:
        if (token_started) {
            buf[buf_idx] = '\0';
            if (*count >= capacity) {
                capacity *= 2;
                tokens = xrealloc(tokens, (capacity + 1) * sizeof(char*));
            }
            tokens[(*count)++] = xstrdup(buf);
        }
    }
    
    tokens[*count] = NULL;
    return tokens;
}

Pipeline *parse_pipeline(const char *line) {
    int token_count;
    char **tokens = tokenize_input(line, &token_count);
    if (!tokens) return NULL;

    Pipeline *p = xmalloc(sizeof(Pipeline));
    memset(p, 0, sizeof(Pipeline));

    int t_idx = 0;
    // Current command segment being built
    Command *curr = &p->segments[0];
    curr->builtin_idx = -1;

    // Allocate initial args array for the first command
    curr->args = xmalloc((MAX_ARGS + 1) * sizeof(char*));

    while (t_idx < token_count) {
        char *tok = tokens[t_idx];

        if (strcmp(tok, "|") == 0) {
            if (curr->arg_count == 0 && !curr->input_file) {
                fprintf(stderr, "%s: syntax error near unexpected token `|'\n", SHELL_NAME);
                free_pipeline(p); free_str_array(tokens); return NULL;
            }
            curr->args[curr->arg_count] = NULL; // null terminate current arg list
            
            p->num_segments++;
            if (p->num_segments >= MAX_PIPELINE_SEGMENTS) {
                fprintf(stderr, "%s: pipeline too deep\n", SHELL_NAME);
                free_pipeline(p); free_str_array(tokens); return NULL;
            }
            curr = &p->segments[p->num_segments];
            curr->args = xmalloc((MAX_ARGS + 1) * sizeof(char*));
            curr->builtin_idx = -1;
            t_idx++;
            continue;
        }

        // Redirection Handling
        if (strcmp(tok, "<") == 0) {
            if (++t_idx >= token_count) goto syntax_err;
            if (curr->input_file) free(curr->input_file);
            curr->input_file = xstrdup(tokens[t_idx]);
        } 
        else if (strcmp(tok, ">") == 0 || strcmp(tok, "1>") == 0) {
            if (++t_idx >= token_count) goto syntax_err;
            if (curr->output_stdout) free(curr->output_stdout);
            curr->output_stdout = xstrdup(tokens[t_idx]);
            curr->append_stdout = false;
        }
        else if (strcmp(tok, ">>") == 0 || strcmp(tok, "1>>") == 0) {
            if (++t_idx >= token_count) goto syntax_err;
            if (curr->output_stdout) free(curr->output_stdout);
            curr->output_stdout = xstrdup(tokens[t_idx]);
            curr->append_stdout = true;
        }
        else if (strcmp(tok, "2>") == 0) {
            if (++t_idx >= token_count) goto syntax_err;
            if (curr->output_stderr) free(curr->output_stderr);
            curr->output_stderr = xstrdup(tokens[t_idx]);
            curr->append_stderr = false;
        }
        else if (strcmp(tok, "2>>") == 0) {
            if (++t_idx >= token_count) goto syntax_err;
            if (curr->output_stderr) free(curr->output_stderr);
            curr->output_stderr = xstrdup(tokens[t_idx]);
            curr->append_stderr = true;
        }
        else {
            // Regular argument
            if (curr->arg_count < MAX_ARGS) {
                curr->args[curr->arg_count++] = xstrdup(tok);
            }
        }
        t_idx++;
    }

    // Finalize last segment
    curr->args[curr->arg_count] = NULL;
    p->num_segments++;

    // Check builtins
    for (int i = 0; i < p->num_segments; i++) {
        if (p->segments[i].arg_count > 0) {
            for (int b = 0; BUILTINS[b].name; b++) {
                if (strcmp(p->segments[i].args[0], BUILTINS[b].name) == 0) {
                    p->segments[i].builtin_idx = b;
                    break;
                }
            }
        }
    }

    free_str_array(tokens);
    return p;

syntax_err:
    fprintf(stderr, "%s: syntax error near redirection\n", SHELL_NAME);
    free_pipeline(p);
    free_str_array(tokens);
    return NULL;
}

void free_pipeline(Pipeline *p) {
    if (!p) return;
    for (int i = 0; i < p->num_segments; i++) {
        free_str_array(p->segments[i].args);
        free(p->segments[i].input_file);
        free(p->segments[i].output_stdout);
        free(p->segments[i].output_stderr);
    }
    free(p);
}

// ============================================================================
// EXECUTOR (Pipes & Forks)
// ============================================================================

char *find_executable(const char *cmd) {
    if (!cmd || !*cmd) return NULL;
    if (strchr(cmd, '/')) {
        return (access(cmd, X_OK) == 0) ? xstrdup(cmd) : NULL;
    }

    char *path_env = getenv("PATH");
    if (!path_env) return NULL;

    char *path_dup = xstrdup(path_env);
    char *dir = strtok(path_dup, ":");
    char full_path[PATH_BUF_SIZE];
    char *result = NULL;

    while (dir) {
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, cmd);
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & S_IXUSR)) {
            result = xstrdup(full_path);
            break;
        }
        dir = strtok(NULL, ":");
    }
    free(path_dup);
    return result;
}

int setup_redirection(Command *cmd) {
    if (cmd->input_file) {
        int fd = open(cmd->input_file, O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "%s: %s: %s\n", SHELL_NAME, cmd->input_file, strerror(errno));
            return -1;
        }
        dup2(fd, STDIN_FILENO);
        close(fd);
    }

    if (cmd->output_stdout) {
        int flags = O_WRONLY | O_CREAT | (cmd->append_stdout ? O_APPEND : O_TRUNC);
        int fd = open(cmd->output_stdout, flags, 0666);
        if (fd == -1) {
            fprintf(stderr, "%s: %s: %s\n", SHELL_NAME, cmd->output_stdout, strerror(errno));
            return -1;
        }
        dup2(fd, STDOUT_FILENO);
        close(fd);
    }

    if (cmd->output_stderr) {
        int flags = O_WRONLY | O_CREAT | (cmd->append_stderr ? O_APPEND : O_TRUNC);
        int fd = open(cmd->output_stderr, flags, 0666);
        if (fd == -1) {
            fprintf(stderr, "%s: %s: %s\n", SHELL_NAME, cmd->output_stderr, strerror(errno));
            return -1;
        }
        dup2(fd, STDERR_FILENO);
        close(fd);
    }
    return 0;
}

int execute_pipeline(Pipeline *p) {
    if (!p || p->num_segments == 0) return 0;

    int pipe_fd[2];
    int input_fd = STDIN_FILENO; // Start with standard input
    int last_status = 0;

    for (int i = 0; i < p->num_segments; i++) {
        Command *cmd = &p->segments[i];
        bool is_last = (i == p->num_segments - 1);
        
        // Prepare pipe for next segment if not last
        if (!is_last) {
            if (pipe(pipe_fd) == -1) {
                perror("pipe");
                return 1;
            }
        }

        // Builtin Logic (only runs in parent if it's the ONLY command, e.g. 'cd')
        if (p->num_segments == 1 && cmd->builtin_idx != -1) {
            // Save Stdout/Stderr before redirect
            int saved_stdout = dup(STDOUT_FILENO);
            int saved_stderr = dup(STDERR_FILENO);
            int saved_stdin = dup(STDIN_FILENO);

            if (setup_redirection(cmd) == 0) {
                last_status = BUILTINS[cmd->builtin_idx].handler(cmd->arg_count, cmd->args);
            } else {
                last_status = 1;
            }

            // Restore
            dup2(saved_stdout, STDOUT_FILENO); close(saved_stdout);
            dup2(saved_stderr, STDERR_FILENO); close(saved_stderr);
            dup2(saved_stdin, STDIN_FILENO); close(saved_stdin);
            return last_status;
        }

        // Forking for external or piped builtins
        cmd->pid = fork();
        if (cmd->pid == -1) {
            perror("fork");
            return 1;
        }

        if (cmd->pid == 0) {
            // --- CHILD PROCESS ---
            
            // Restore default signal handlers
            signal(SIGINT, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);

            // Connect Input (from prev pipe or stdin)
            if (input_fd != STDIN_FILENO) {
                dup2(input_fd, STDIN_FILENO);
                close(input_fd);
            }

            // Connect Output (to next pipe or stdout)
            if (!is_last) {
                dup2(pipe_fd[1], STDOUT_FILENO);
                close(pipe_fd[0]); // Close read end
                close(pipe_fd[1]); // Close write end
            }

            // Apply File Redirections
            if (setup_redirection(cmd) == -1) {
                exit(EXIT_FAILURE);
            }

            // Execute
            if (cmd->arg_count == 0) exit(EXIT_SUCCESS);

            if (cmd->builtin_idx != -1) {
                exit(BUILTINS[cmd->builtin_idx].handler(cmd->arg_count, cmd->args));
            } else {
                char *exe = find_executable(cmd->args[0]);
                if (!exe) {
                    fprintf(stderr, "%s: command not found\n", cmd->args[0]);
                    exit(127);
                }
                execv(exe, cmd->args);
                // Exec failed
                fprintf(stderr, "%s: %s\n", cmd->args[0], strerror(errno));
                exit(126);
            }
        }

        // --- PARENT PROCESS ---
        if (input_fd != STDIN_FILENO) close(input_fd); // Close used read end
        if (!is_last) {
            close(pipe_fd[1]); // Close write end of current pipe
            input_fd = pipe_fd[0]; // Save read end for next command
        }
    }

    // Wait for all children
    for (int i = 0; i < p->num_segments; i++) {
        if (p->segments[i].pid > 0) {
            int status;
            waitpid(p->segments[i].pid, &status, 0);
            if (WIFEXITED(status)) last_status = WEXITSTATUS(status);
            else if (WIFSIGNALED(status)) last_status = 128 + WTERMSIG(status);
        }
    }

    return last_status;
}

// ============================================================================
// BUILTINS
// ============================================================================

int builtin_echo(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("%s%s", argv[i], (i < argc - 1) ? " " : "");
    }
    printf("\n");
    return 0;
}

int builtin_cd(int argc, char **argv) {
    const char *path;
    
    // Handle "cd" (no args) OR "cd ~"
    if (argc < 2 || strcmp(argv[1], "~") == 0) {
        path = getenv("HOME");
        if (!path) { 
            fprintf(stderr, "cd: HOME not set\n"); 
            return 1; 
        }
    } else {
        path = argv[1];
    }

    if (chdir(path) != 0) {
        // "cd: No such file or directory" is printed by perror
        fprintf(stderr, "cd: %s: ", path); 
        perror(""); // prints the error message (e.g. "No such file or directory")
        return 1;
    }
    
    // Update PWD environment variable
    char cwd[PATH_BUF_SIZE];
    if (getcwd(cwd, sizeof(cwd))) {
        setenv("PWD", cwd, 1);
    }
    return 0;
}

int builtin_pwd(int argc, char **argv) {
    char cwd[PATH_BUF_SIZE];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("%s\n", cwd);
        return 0;
    }
    perror("pwd");
    return 1;
}

int builtin_exit(int argc, char **argv) {
    if (argc > 1) {
        int code = atoi(argv[1]);
        exit(code);
    }
    exit(0);
}

int builtin_type(int argc, char **argv) {
    if (argc < 2) return 0;
    
    for (int i = 1; i < argc; i++) {
        bool found_builtin = false;
        for (int b = 0; BUILTINS[b].name; b++) {
            if (strcmp(argv[i], BUILTINS[b].name) == 0) {
                printf("%s is a shell builtin\n", argv[i]);
                found_builtin = true;
                break;
            }
        }
        if (found_builtin) continue;

        char *path = find_executable(argv[i]);
        if (path) {
            printf("%s is %s\n", argv[i], path);
            free(path);
        } else {
            printf("%s: not found\n", argv[i]);
        }
    }
    return 0;
}

int builtin_history(int argc, char **argv) {
    // 1. Handle File Operations (flags usually require a filename arg)
    if (argc >= 3) {
        // Handle -a: Append new entries only
        if (strcmp(argv[1], "-a") == 0) {
            int new_entries = history_length - last_history_sync;
            if (new_entries > 0) {
                if (append_history(new_entries, argv[2]) != 0) {
                    perror("history");
                    return 1;
                }
                last_history_sync = history_length;
            }
            return 0;
        } 
        // Handle -w: Overwrite file with current history
        else if (strcmp(argv[1], "-w") == 0) {
            if (write_history(argv[2]) != 0) {
                perror("history");
                return 1;
            }
            return 0;
        }
        // Handle -r: Read history from file
        else if (strcmp(argv[1], "-r") == 0) {
            if (read_history(argv[2]) != 0) {
                perror("history");
                return 1;
            }
            return 0;
        }
    }

    // 2. Determine print range
    int start_index = 0;
    
    // Check for "history <n>" (numeric limit)
    if (argc == 2 && isdigit(argv[1][0])) {
        int limit = atoi(argv[1]);
        if (limit > 0 && limit < history_length) {
            start_index = history_length - limit;
        }
    }

    // 3. Print History
    HIST_ENTRY **list = history_list();
    if (!list) return 0;
    
    for (int i = start_index; i < history_length; i++) {
         if (list[i]) {
            printf("%5d  %s\n", i + history_base, list[i]->line);
         }
    }
    return 0;
}

// ============================================================================
// AUTOCOMPLETE & SIGNALS
// ============================================================================

char *completion_generator(const char *text, int state) {
    static size_t len;
    
    if (state == 0) {
        sa_free(&completion_matches);
        sa_init(&completion_matches, 32);
        len = strlen(text);

        // 1. Add matching builtins
        for (int i = 0; BUILTINS[i].name; i++) {
            if (strncmp(BUILTINS[i].name, text, len) == 0) {
                sa_add(&completion_matches, xstrdup(BUILTINS[i].name));
            }
        }

        // 2. Add matching executables in PATH
        char *path = getenv("PATH");
        if (path) {
            char *pdup = xstrdup(path);
            char *dir = strtok(pdup, ":");
            while (dir) {
                DIR *d = opendir(dir);
                if (d) {
                    struct dirent *ent;
                    while ((ent = readdir(d)) != NULL) {
                        if (ent->d_name[0] == '.') continue;
                        if (strncmp(ent->d_name, text, len) == 0) {
                            sa_add(&completion_matches, xstrdup(ent->d_name));
                        }
                    }
                    closedir(d);
                }
                dir = strtok(NULL, ":");
            }
            free(pdup);
        }
        sa_sort_unique(&completion_matches);
        completion_idx = 0;
    }

    if (completion_idx < completion_matches.count) {
        return xstrdup(completion_matches.elements[completion_idx++]);
    }
    return NULL;
}

char **shell_completion(const char *text, int start, int end) {
    rl_attempted_completion_over = 1;
    // Basic heuristic: if at start of line, complete commands. Otherwise, files.
    if (start == 0) {
        return rl_completion_matches(text, completion_generator);
    }
    // Default to filename completion
    return NULL; 
}

void cleanup_shell(void) {
    char *histfile = getenv("HISTFILE");
    if (histfile && *histfile) {
        write_history(histfile);
    }
    clear_history();
    sa_free(&completion_matches);
}

void setup_signals(void) {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN; // Ignore Ctrl+C in parent shell
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    // Ignore SIGTTOU to prevent shell from freezing when tcsetpgrp is used (future proofing)
    signal(SIGTTOU, SIG_IGN);
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv) {
    // Setup
    setup_signals();
    atexit(cleanup_shell);
    sa_init(&completion_matches, 16);

    // Readline setup
    rl_attempted_completion_function = shell_completion;
    using_history();
    
    char *histfile = getenv("HISTFILE");
    if (histfile && *histfile) {
        read_history(histfile);
    }

    char *line;
    while ((line = readline("$ ")) != NULL) {
        // Skip empty lines
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) {
            free(line);
            continue;
        }

        add_history(line);
        
        Pipeline *pipeline = parse_pipeline(line);
        if (pipeline) {
            execute_pipeline(pipeline);
            free_pipeline(pipeline);
        }

        free(line);
    }

    // Newline on exit (Ctrl+D)
    printf("\n");
    return 0;
}
