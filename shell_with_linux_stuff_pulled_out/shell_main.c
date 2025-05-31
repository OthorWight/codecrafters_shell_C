#include "os_compat.h" // Main include for OS functions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
// #include <errno.h> // Use os_get_last_error_code() and os_get_last_error_string()

#define MAX_INPUT_LENGTH 256
#define FULL_PATH_BUFFER_SIZE 4096 // PATH_MAX is better but this was original
#define MAX_ARGS 64
#define MAX_PIPELINE_SEGMENTS 16

// Forward declarations for builtins
int builtin_echo(int argc, char **argv);
int builtin_exit_shell(int argc, char **argv);
int builtin_type(int argc, char **argv);
int builtin_pwd(int argc, char **argv);
int builtin_cd(int argc, char **argv);
int builtin_history(int argc, char **argv);

// Forward declaration for argument parsing (remains mostly the same)
char **parse_input(const char *input_line_const, int *arg_count);
void free_parsed_args(char **args);

typedef struct Pipeline Pipeline; // Keep forward declaration
void free_pipeline_resources(Pipeline *pipeline);

typedef int (*builtin_handler_func)(int argc, char **argv);

typedef struct {
    const char *name;
    builtin_handler_func handler;
} BuiltinCommandEntry;

// This table remains in the main shell logic
BuiltinCommandEntry BUILTIN_COMMAND_TABLE[] = {
    {"echo", builtin_echo}, {"exit", builtin_exit_shell}, {"type", builtin_type},
    {"pwd", builtin_pwd}, {"cd", builtin_cd},
    {"history", builtin_history},
    {NULL, NULL}
};


// Dynamic Array implementation (can be moved to its own utils.c/h later)
// This is generic and doesn't need OSAL.
typedef struct {
    char **elements;
    int count;
    int capacity;
} DynamicArray;

void da_init(DynamicArray *da, int initial_capacity) {
    da->elements = malloc(initial_capacity * sizeof(char*));
    if (!da->elements && initial_capacity > 0) {
        perror("malloc for dynamic array elements"); // Standard perror is fine here
        exit(EXIT_FAILURE);
    } else if (initial_capacity == 0) {
        da->elements = NULL;
    }
    da->count = 0;
    da->capacity = initial_capacity;
}

void da_add(DynamicArray *da, char *element) {
    if (da->count == da->capacity) {
        da->capacity = (da->capacity == 0) ? 10 : da->capacity * 2;
        char **new_elements = realloc(da->elements, da->capacity * sizeof(char*));
        if (!new_elements) {
            perror("realloc for dynamic array elements");
            if (element) free(element); // Free the passed element if realloc fails
            return;
        }
        da->elements = new_elements;
    }
    da->elements[da->count++] = element;
}

void da_free(DynamicArray *da, bool free_elements_content) {
    if (free_elements_content) {
        for (int i = 0; i < da->count; i++) {
            if (da->elements[i]) free(da->elements[i]);
        }
    }
    if (da->elements) free(da->elements);
    da->elements = NULL;
    da->count = 0;
    da->capacity = 0;
}

int compare_string_pointers(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

void da_sort(DynamicArray *da) {
    if (da->count > 1) {
        qsort(da->elements, da->count, sizeof(char*), compare_string_pointers);
    }
}

void da_unique(DynamicArray *da) {
    if (da->count <= 1) return;
    da_sort(da);

    int j = 0;
    for (int i = 1; i < da->count; i++) {
        if (strcmp(da->elements[j], da->elements[i]) != 0) {
            j++;
            if (j != i) {
                da->elements[j] = da->elements[i];
            }
        } else {
            free(da->elements[i]);
            da->elements[i] = NULL;
        }
    }
    da->count = j + 1;
}

// --- Completion Logic ---
static DynamicArray current_completion_matches; // Used by command_generator_func
static int current_completion_idx;             // Used by command_generator_func

// This is the generator function that os_perform_completion_matches will call
char* command_generator_func(const char* text, int state) {
    if (state == 0) { // Initial call for this completion attempt
        da_free(&current_completion_matches, true);
        da_init(&current_completion_matches, 10);
        current_completion_idx = 0;

        // 1. Add builtins
        for (int i = 0; BUILTIN_COMMAND_TABLE[i].name != NULL; i++) {
            if (strncmp(BUILTIN_COMMAND_TABLE[i].name, text, strlen(text)) == 0) {
                char* match = strdup(BUILTIN_COMMAND_TABLE[i].name);
                if (match) da_add(&current_completion_matches, match);
            }
        }

        // 2. Add executables from PATH
        char *path_env_full = os_get_env("PATH"); // Use OSAL
        if (path_env_full) {
            char *path_env_copy = strdup(path_env_full); // strdup is fine
            if (path_env_copy) {
                char path_sep_str[2] = {os_get_path_separator_char(), '\0'};
                char *path_dir = strtok(path_env_copy, path_sep_str);
                while (path_dir) {
                    os_dir_t d = os_open_dir(path_dir); // Use OSAL
                    if (d) {
                        os_dir_entry_t entry;
                        while (os_read_dir_entry(d, &entry)) { // Use OSAL
                            // Skip "." and ".."
                            if (entry.name[0] == '.' && (entry.name[1] == '\0' || (entry.name[1] == '.' && entry.name[2] == '\0'))) {
                                continue;
                            }
                            if (strncmp(entry.name, text, strlen(text)) == 0) {
                                char full_exe_path[FULL_PATH_BUFFER_SIZE];
                                size_t path_dir_len = strlen(path_dir);
                                size_t entry_name_len = strlen(entry.name);
                                size_t content_len;

                                if (path_dir_len > 0 && path_dir[path_dir_len - 1] == '/') {
                                    content_len = path_dir_len + entry_name_len;
                                    if (content_len >= sizeof(full_exe_path)) { // Content must be < buffer size for null terminator
                                        // fprintf(stderr, "Completion path content too long (A): %s%s\n", path_dir, entry.name);
                                        continue; 
                                    }
                                    snprintf(full_exe_path, sizeof(full_exe_path), "%s%s", path_dir, entry.name);
                                } else {
                                    content_len = path_dir_len + 1 + entry_name_len; // +1 for '/'
                                    if (content_len >= sizeof(full_exe_path)) { // Content must be < buffer size for null terminator
                                        // This is the path leading to the warning (line 176 approximately)
                                        // fprintf(stderr, "Completion path content too long (B): %s/%s\n", path_dir, entry.name);
                                        continue; 
                                    }
                                    // This specific snprintf is what GCC is warning about for line 176
                                    #pragma GCC diagnostic push
                                    #pragma GCC diagnostic ignored "-Wformat-truncation"
                                    snprintf(full_exe_path, sizeof(full_exe_path), "%s/%s", path_dir, entry.name);
                                    #pragma GCC diagnostic pop
                                }

                                // Check if path exists and is executable (after successful snprintf)
                                if (os_file_exists_and_is_accessible(full_exe_path, true)) { // This requires full_exe_path to be null-terminated
                                    if (!os_is_directory(full_exe_path)) {
                                         char* match = strdup(entry.name);
                                         if (match) da_add(&current_completion_matches, match);
                                    }
                                }
                            }
                        }
                        os_close_dir(d); // Use OSAL
                    }
                    path_dir = strtok(NULL, path_sep_str);
                }
                free(path_env_copy);
            }
            free(path_env_full); // From os_get_env
        }
        da_sort(&current_completion_matches);
        da_unique(&current_completion_matches);
    }

    // Return next match
    if (current_completion_idx < current_completion_matches.count) {
        // The generator is expected to return a new string each time for readline
        return strdup(current_completion_matches.elements[current_completion_idx++]);
    }

    return NULL; // No more matches
}

// This is the function we register with os_set_completion_handler
char** shell_completion_func(const char* text_line_buffer, int start_index, int end_index) {
    os_attempted_completion_over = 1; // Signal that we are attempting completion

    bool first_word_completion = true;
    for (int i = 0; i < start_index; i++) {
        if (!isspace((unsigned char)text_line_buffer[i])) {
            first_word_completion = false;
            break;
        }
    }

    if (!first_word_completion) {
        // If not completing the first word (command), don't attempt for now.
        // This shell's completion is basic and only does commands.
        // To allow readline to try filename completion, set over to 0.
        os_attempted_completion_over = 0;
        return NULL;
    }

    // Extract the word being completed
    char *word_to_complete = strndup(text_line_buffer + start_index, end_index - start_index);
    if (!word_to_complete) {
        return NULL; // Allocation error
    }

    char **matches = os_perform_completion_matches(word_to_complete, command_generator_func); // Use OSAL
    free(word_to_complete);
    return matches;
}


// --- Pipeline and Command Structures ---
typedef struct {
    char **args;
    int arg_count;
    char *input_file;
    char *output_file_stdout;
    bool append_stdout;
    char *output_file_stderr;
    bool append_stderr;
    int builtin_idx; // Index in BUILTIN_COMMAND_TABLE, -1 if not builtin, -2 for syntax error
    os_pid_t pid;      // Use os_pid_t
    int exit_status;
} CommandSegment;

struct Pipeline {
    CommandSegment segments[MAX_PIPELINE_SEGMENTS];
    int num_segments;
};

// Function to find executable (now uses OSAL)
// This local helper is now just a wrapper or can be removed if os_find_executable_in_path is used directly
char *local_find_executable_in_path(const char *command_name) {
    return os_find_executable_in_path(command_name);
}


void parse_single_segment(const char *segment_str, CommandSegment *cmd_seg) {
    memset(cmd_seg, 0, sizeof(CommandSegment));
    cmd_seg->builtin_idx = -1;
    cmd_seg->pid = OS_INVALID_PID; // Initialize pid

    if (segment_str == NULL || strlen(segment_str) == 0) {
        return;
    }

    int num_segment_tokens;
    char **segment_tokens = parse_input(segment_str, &num_segment_tokens);

    if (segment_tokens == NULL || num_segment_tokens == 0) {
        if (segment_tokens) free_parsed_args(segment_tokens);
        return;
    }

    cmd_seg->args = malloc((num_segment_tokens + 1) * sizeof(char *));
    if (!cmd_seg->args) {
        perror("malloc for cmd_seg->args");
        free_parsed_args(segment_tokens);
        return;
    }

    int current_token_idx = 0;
    cmd_seg->arg_count = 0;
    bool syntax_error = false;

    // Parse command and its arguments
    while (current_token_idx < num_segment_tokens) {
        char *token = segment_tokens[current_token_idx];
        // Check if token is a redirection operator
        if (strcmp(token, "<") == 0 || strcmp(token, ">") == 0 || strcmp(token, ">>") == 0 ||
            strcmp(token, "2>") == 0 || strcmp(token, "2>>") == 0 ||
            strcmp(token, "1>") == 0 || strcmp(token, "1>>") == 0) {
            break; // Start of redirection part
        }
        cmd_seg->args[cmd_seg->arg_count++] = strdup(token);
        if (!cmd_seg->args[cmd_seg->arg_count -1]) {
            perror("strdup for command argument");
            syntax_error = true; break;
        }
        current_token_idx++;
    }
    cmd_seg->args[cmd_seg->arg_count] = NULL; // Null-terminate the argument list

    // Parse redirections
    while (current_token_idx < num_segment_tokens && !syntax_error) {
        char *op_token = segment_tokens[current_token_idx++];
        if (current_token_idx >= num_segment_tokens) {
            fprintf(stderr, "bash: syntax error near unexpected token `newline'\n");
            syntax_error = true; break;
        }
        char *filename_token = segment_tokens[current_token_idx++];

        // Check for syntax error like `> >`
        if (strcmp(filename_token, "<") == 0 || strcmp(filename_token, ">") == 0 || strcmp(filename_token, ">>") == 0 ||
            strcmp(filename_token, "2>") == 0 || strcmp(filename_token, "2>>") == 0 ||
            strcmp(filename_token, "1>") == 0 || strcmp(filename_token, "1>>") == 0) {
            fprintf(stderr, "bash: syntax error near unexpected token `%s'\n", filename_token);
            syntax_error = true; break;
        }


        if (strcmp(op_token, "<") == 0) {
            if (cmd_seg->input_file) { free(cmd_seg->input_file); }
            cmd_seg->input_file = strdup(filename_token);
            if (!cmd_seg->input_file) { perror("strdup input_file"); syntax_error=true; }
        } else if (strcmp(op_token, ">") == 0 || strcmp(op_token, "1>") == 0) {
            if (cmd_seg->output_file_stdout) { free(cmd_seg->output_file_stdout); }
            cmd_seg->output_file_stdout = strdup(filename_token);
            cmd_seg->append_stdout = false;
            if (!cmd_seg->output_file_stdout) { perror("strdup output_file_stdout"); syntax_error=true; }
        } else if (strcmp(op_token, ">>") == 0 || strcmp(op_token, "1>>") == 0) {
            if (cmd_seg->output_file_stdout) { free(cmd_seg->output_file_stdout); }
            cmd_seg->output_file_stdout = strdup(filename_token);
            cmd_seg->append_stdout = true;
            if (!cmd_seg->output_file_stdout) { perror("strdup output_file_stdout append"); syntax_error=true; }
        } else if (strcmp(op_token, "2>") == 0) {
            if (cmd_seg->output_file_stderr) { free(cmd_seg->output_file_stderr); }
            cmd_seg->output_file_stderr = strdup(filename_token);
            cmd_seg->append_stderr = false;
            if (!cmd_seg->output_file_stderr) { perror("strdup output_file_stderr"); syntax_error=true; }
        } else if (strcmp(op_token, "2>>") == 0) {
            if (cmd_seg->output_file_stderr) { free(cmd_seg->output_file_stderr); }
            cmd_seg->output_file_stderr = strdup(filename_token);
            cmd_seg->append_stderr = true;
            if (!cmd_seg->output_file_stderr) { perror("strdup output_file_stderr append"); syntax_error=true; }
        } else {
            // This case should ideally not be reached if the first loop correctly stops at operators
            fprintf(stderr, "bash: syntax error near unexpected token `%s'\n", op_token);
            syntax_error = true;
        }
        if (syntax_error) break;
    }

    free_parsed_args(segment_tokens);

    if (syntax_error) {
        // Cleanup on syntax error
        if (cmd_seg->args) {
            for (int i = 0; cmd_seg->args[i] != NULL; i++) free(cmd_seg->args[i]);
            free(cmd_seg->args);
            cmd_seg->args = NULL;
        }
        cmd_seg->arg_count = 0;
        if (cmd_seg->input_file) { free(cmd_seg->input_file); cmd_seg->input_file = NULL; }
        if (cmd_seg->output_file_stdout) { free(cmd_seg->output_file_stdout); cmd_seg->output_file_stdout = NULL; }
        if (cmd_seg->output_file_stderr) { free(cmd_seg->output_file_stderr); cmd_seg->output_file_stderr = NULL; }
        cmd_seg->builtin_idx = -2; // Mark as syntax error
        return;
    }

    // Check if the command is a builtin
    if (cmd_seg->arg_count > 0) {
        for (int i = 0; BUILTIN_COMMAND_TABLE[i].name != NULL; i++) {
            if (strcmp(cmd_seg->args[0], BUILTIN_COMMAND_TABLE[i].name) == 0) {
                cmd_seg->builtin_idx = i;
                break;
            }
        }
    }
}


Pipeline* parse_line_into_pipeline(const char *line_buffer_const) {
    if (!line_buffer_const || !*line_buffer_const) return NULL;

    Pipeline *pipeline = malloc(sizeof(Pipeline));
    if (!pipeline) {
        perror("malloc for Pipeline");
        return NULL;
    }
    memset(pipeline, 0, sizeof(Pipeline));

    char *line_copy = strdup(line_buffer_const);
    if (!line_copy) {
        perror("strdup in parse_line_into_pipeline");
        free(pipeline);
        return NULL;
    }

    char *current_segment_str = line_copy;
    char *next_pipe_char;
    bool syntax_error_in_pipeline = false;

    while (pipeline->num_segments < MAX_PIPELINE_SEGMENTS) {
        next_pipe_char = strchr(current_segment_str, '|');
        if (next_pipe_char) {
            *next_pipe_char = '\0'; // Null-terminate current segment string
        }

        // Trim whitespace from the current segment string
        char *start = current_segment_str;
        while (*start && isspace((unsigned char)*start)) start++;

        char *end = start + strlen(start) - 1;
        while (end >= start && isspace((unsigned char)*end)) end--;
        *(end + 1) = '\0';

        if (strlen(start) == 0) { // Empty segment
            // Check if this empty segment is problematic (e.g., "cmd | | cmd" or "| cmd" or "cmd |")
            if ( (pipeline->num_segments == 0 && next_pipe_char) || // Starts with pipe, e.g., "| cmd"
                 (pipeline->num_segments > 0 && next_pipe_char) || // Double pipe, e.g., "cmd1 | | cmd2"
                 (current_segment_str == line_copy && next_pipe_char && strlen(next_pipe_char + 1) == 0 && strlen(start)==0) || // " | "
                 (next_pipe_char && !*(next_pipe_char +1) && strlen(start)==0) // "cmd | " (empty segment after pipe)
                ) {
                if (next_pipe_char) { // An actual pipe character was involved with this empty segment
                    fprintf(stderr, "bash: syntax error near unexpected token `|'\n");
                    syntax_error_in_pipeline = true;
                    break;
                }
                 // If it's just an empty line or empty segment without a problematic pipe, it might be skipped
            }
             // If it's an empty segment but not causing a pipe syntax error, just skip to next.
        }


        if (strlen(start) > 0) { // If there's something to parse
             parse_single_segment(start, &pipeline->segments[pipeline->num_segments]);
             if (pipeline->segments[pipeline->num_segments].builtin_idx == -2) { // Syntax error in segment
                 syntax_error_in_pipeline = true;
                 break;
             }
             pipeline->num_segments++;
        }


        if (next_pipe_char) {
            current_segment_str = next_pipe_char + 1;
            if (pipeline->num_segments == MAX_PIPELINE_SEGMENTS && strchr(current_segment_str, '|')) {
                 fprintf(stderr, "bash: too many pipe segments\n"); // Or your shell's error
                 syntax_error_in_pipeline = true; // Or handle as per your shell's design
                 break;
            }
        } else {
            break; // No more pipe characters
        }
    }

    free(line_copy);
    if (syntax_error_in_pipeline || pipeline->num_segments == 0) {
        // If there was a syntax error, or if the line resulted in no actual commands (e.g. "   |   ")
        free_pipeline_resources(pipeline); // Free any partially allocated segments
        return NULL;
    }
    return pipeline;
}


void free_pipeline_resources(Pipeline *pipeline) {
    if (!pipeline) return;
    for (int i = 0; i < pipeline->num_segments; i++) {
        CommandSegment *seg = &pipeline->segments[i];
        if (seg->args) {
            for (int j = 0; seg->args[j] != NULL; j++) {
                free(seg->args[j]);
            }
            free(seg->args);
        }
        if (seg->input_file) free(seg->input_file);
        if (seg->output_file_stdout) free(seg->output_file_stdout);
        if (seg->output_file_stderr) free(seg->output_file_stderr);
        // pid is just a value, no freeing. exit_status is int.
    }
    free(pipeline);
}


int execute_pipeline(Pipeline *pipeline) {
    if (!pipeline || pipeline->num_segments == 0) return 0;

    int num_cmds = pipeline->num_segments;
    int last_cmd_status = 0;

    // Save original stdio to restore later
    int shell_original_stdin = os_dup(OS_STDIN_FD);
    int shell_original_stdout = os_dup(OS_STDOUT_FD);
    int shell_original_stderr = os_dup(OS_STDERR_FD);

    if (shell_original_stdin == -1 || shell_original_stdout == -1 || shell_original_stderr == -1) {
        perror("execute_pipeline: os_dup original shell stdio"); // Use perror with context
        if(shell_original_stdin != -1) os_close_fd(shell_original_stdin);
        if(shell_original_stdout != -1) os_close_fd(shell_original_stdout);
        if(shell_original_stderr != -1) os_close_fd(shell_original_stderr);
        return 255; // Error status
    }

    int input_fd_for_current_cmd = shell_original_stdin; // First command reads from shell's original stdin
    int pipe_fds[2] = {-1, -1}; // To store [read_end, write_end] of a pipe

    for (int i = 0; i < num_cmds; i++) {
        CommandSegment *cmd = &pipeline->segments[i];
        bool is_last_cmd = (i == num_cmds - 1);

        // Default FDs for the current command
        int current_cmd_stdin = input_fd_for_current_cmd; // From previous pipe or original stdin
        int current_cmd_stdout = shell_original_stdout;   // Default to original stdout
        int current_cmd_stderr = shell_original_stderr;   // Default to original stderr

        int next_input_fd_temp = -1; // This will be the read end of the pipe for the *next* command

        // If not the last command, set up a pipe for its stdout to go to the next command's stdin
        if (!is_last_cmd) {
            if (!os_create_pipe(&pipe_fds[0], &pipe_fds[1])) {
                perror("execute_pipeline: os_create_pipe");
                last_cmd_status = 1; // General error
                // Clean up FDs that were meant for this command
                if (input_fd_for_current_cmd != shell_original_stdin) os_close_fd(input_fd_for_current_cmd);
                goto cleanup_and_exit_pipeline; // Critical error, abort pipeline
            }
            current_cmd_stdout = pipe_fds[1]; // Current command writes to the pipe's write end
            next_input_fd_temp = pipe_fds[0]; // Next command will read from the pipe's read end
        }

        // Handle I/O redirections specified by the user
        int user_redirect_in_fd = -1;
        int user_redirect_out_fd = -1;
        int user_redirect_err_fd = -1;
        bool redirection_error = false;

        if (cmd->input_file) {
            user_redirect_in_fd = os_open_file(cmd->input_file, OS_OPEN_READONLY, 0);
            if (user_redirect_in_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->input_file, os_get_last_error_string());
                redirection_error = true; cmd->exit_status = 1;
            } else {
                // If current_cmd_stdin was a pipe read end from a previous command, close it.
                if (current_cmd_stdin != shell_original_stdin && current_cmd_stdin != input_fd_for_current_cmd) {
                     os_close_fd(current_cmd_stdin); // This case might be rare if logic is correct
                } else if (current_cmd_stdin == input_fd_for_current_cmd && input_fd_for_current_cmd != shell_original_stdin) {
                    // This was the read end of a pipe connecting to the previous command.
                    // It's now being replaced by file input, so it should be closed IF this command
                    // isn't the one that was supposed to use it (i.e., if it's not input_fd_for_current_cmd).
                    // However, input_fd_for_current_cmd is already assigned to current_cmd_stdin.
                    // The original input_fd_for_current_cmd (if it was a pipe) will be closed later
                    // *after* this command (or its child) is done with its input_fd_for_current_cmd.
                }
                current_cmd_stdin = user_redirect_in_fd; // Use the file FD for input
            }
        }

        if (!redirection_error && cmd->output_file_stdout) {
            int flags = OS_OPEN_WRITEONLY | OS_OPEN_CREATE | (cmd->append_stdout ? OS_OPEN_APPEND : OS_OPEN_TRUNCATE);
            user_redirect_out_fd = os_open_file(cmd->output_file_stdout, flags, OS_DEFAULT_FILE_PERMS);
            if (user_redirect_out_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->output_file_stdout, os_get_last_error_string());
                redirection_error = true; cmd->exit_status = 1;
            } else {
                // If current_cmd_stdout was a pipe write end, close it as we're redirecting to a file.
                if (current_cmd_stdout != shell_original_stdout && current_cmd_stdout != pipe_fds[1]) {
                     os_close_fd(current_cmd_stdout); // This case might be rare
                } else if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) {
                    // This command was supposed to write to pipe_fds[1].
                    // Since it's now writing to a file, close the write end of the pipe.
                    // The read end (next_input_fd_temp / pipe_fds[0]) should also be closed if it exists,
                    // as the next command won't get input from this pipe.
                }
                current_cmd_stdout = user_redirect_out_fd;
                if (next_input_fd_temp != -1 && next_input_fd_temp == pipe_fds[0]) {
                    // If output is redirected to a file, the pipe to the next command is broken.
                    // Close the read end of that pipe so the next command gets EOF if it tries to read.
                    os_close_fd(next_input_fd_temp);
                    next_input_fd_temp = -1; // Mark as dealt with
                    if (pipe_fds[0] != -1) pipe_fds[0] = -1; // Mark pipe's read end as closed
                }
            }
        }
        if (!redirection_error && cmd->output_file_stderr) {
            int flags = OS_OPEN_WRITEONLY | OS_OPEN_CREATE | (cmd->append_stderr ? OS_OPEN_APPEND : OS_OPEN_TRUNCATE);
            user_redirect_err_fd = os_open_file(cmd->output_file_stderr, flags, OS_DEFAULT_FILE_PERMS);
            if (user_redirect_err_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->output_file_stderr, os_get_last_error_string());
                redirection_error = true; cmd->exit_status = 1;
            } else {
                if (current_cmd_stderr != shell_original_stderr) os_close_fd(current_cmd_stderr); // Close if it was already redirected (e.g. &> file)
                current_cmd_stderr = user_redirect_err_fd;
            }
        }

        if (redirection_error) {
            last_cmd_status = cmd->exit_status;
            // Close any FDs we opened for redirection before failing
            if (user_redirect_in_fd != -1 && current_cmd_stdin != user_redirect_in_fd) os_close_fd(user_redirect_in_fd);
            if (user_redirect_out_fd != -1 && current_cmd_stdout != user_redirect_out_fd) os_close_fd(user_redirect_out_fd);
            if (user_redirect_err_fd != -1 && current_cmd_stderr != user_redirect_err_fd) os_close_fd(user_redirect_err_fd);

            // If there was a pipe set up for output, and we failed before using it, close its write end.
            if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) {
                os_close_fd(pipe_fds[1]); pipe_fds[1] = -1;
            }
            // The read end (next_input_fd_temp) if it exists, will provide EOF to the next command or be closed.
        } else if (cmd->arg_count == 0 && !(cmd->input_file || cmd->output_file_stdout || cmd->output_file_stderr)) {
             // Empty command segment (e.g. from "cmd1 | | cmd2" after parsing, if not caught as syntax error earlier)
             // or a segment that's just redirections with no command.
             cmd->exit_status = 0; last_cmd_status = 0;
             // If this segment was supposed to provide input to a pipe, the next command will get EOF.
             // The write end of the pipe (current_cmd_stdout if it was pipe_fds[1]) needs to be closed.
        } else if (cmd->arg_count == 0) { // Just redirections, e.g. "> out < in"
            cmd->exit_status = 0; last_cmd_status = 0;
        } else if (cmd->builtin_idx != -1) { // Execute builtin command
            int temp_stdin_dup = os_dup(OS_STDIN_FD);
            int temp_stdout_dup = os_dup(OS_STDOUT_FD);
            int temp_stderr_dup = os_dup(OS_STDERR_FD);

            if (os_dup2(current_cmd_stdin, OS_STDIN_FD) == -1) perror("os_dup2 stdin for builtin");
            if (os_dup2(current_cmd_stdout, OS_STDOUT_FD) == -1) perror("os_dup2 stdout for builtin");
            if (os_dup2(current_cmd_stderr, OS_STDERR_FD) == -1) perror("os_dup2 stderr for builtin");

            // Close the command's specific FDs if they are not the original shell FDs
            // and not the ones we just duped them from (which are now standard FDs).
            if (current_cmd_stdin != shell_original_stdin && current_cmd_stdin != input_fd_for_current_cmd) os_close_fd(current_cmd_stdin);
            if (current_cmd_stdout != shell_original_stdout && current_cmd_stdout != (pipe_fds[1] == -1 ? -2 : pipe_fds[1])) os_close_fd(current_cmd_stdout);
            if (current_cmd_stderr != shell_original_stderr) os_close_fd(current_cmd_stderr);


            cmd->exit_status = BUILTIN_COMMAND_TABLE[cmd->builtin_idx].handler(cmd->arg_count, cmd->args);
            last_cmd_status = cmd->exit_status;
            fflush(stdout); // Ensure output is written before FDs are restored
            fflush(stderr);

            os_dup2(temp_stdin_dup, OS_STDIN_FD); os_close_fd(temp_stdin_dup);
            os_dup2(temp_stdout_dup, OS_STDOUT_FD); os_close_fd(temp_stdout_dup);
            os_dup2(temp_stderr_dup, OS_STDERR_FD); os_close_fd(temp_stderr_dup);

        } else { // Execute external command
            char* exe_path = local_find_executable_in_path(cmd->args[0]);
            if (!exe_path) {
                fprintf(stderr, "%s: command not found\n", cmd->args[0]);
                cmd->exit_status = 127; last_cmd_status = 127;
            } else {
                char **child_argv = malloc((cmd->arg_count + 1) * sizeof(char *));
                if (!child_argv) {
                    perror("malloc for child_argv");
                    free(exe_path);
                    cmd->exit_status = 1; last_cmd_status = 1;
                } else {
                    child_argv[0] = exe_path; // Full path to executable
                    for (int j = 0; j < cmd->arg_count; j++) {
                        child_argv[j + 1] = cmd->args[j]; // Copy original args
                    }
                    child_argv[cmd->arg_count] = NULL; // Null-terminate the argument list
    
                    os_process_start_info_t start_info = {0};
                    start_info.argv = child_argv; // Use the child_argv array
                    start_info.argv[0] = exe_path; // Ensure argv[0] is the full path for os_spawn_process
                    start_info.stdin_fd = current_cmd_stdin;
                    start_info.stdout_fd = current_cmd_stdout;
                    start_info.stderr_fd = current_cmd_stderr;

                    cmd->pid = os_spawn_process(&start_info);

                    if (cmd->pid == OS_INVALID_PID) {
                        perror("execute_pipeline: os_spawn_process");
                        cmd->exit_status = 1; last_cmd_status = 1;
                    }
                    free(child_argv); // Free the child_argv array, but not the strings it points to
                }
                // Original argv[0] (command name) is still in cmd->args[0] for error messages.
                // Restore it if needed, or ensure error messages use the original.
                // For now, we'll assume os_spawn_process doesn't modify the argv strings themselves.
                // And child process will use exe_path.
                // cmd->args[0] = BUILTIN_COMMAND_TABLE[0].name; // This is a placeholder, should be original arg
                                                              // Actually, the original cmd->args[0] is fine.
                                                              // The `exe_path` is passed in start_info.argv[0]
                                                              // but cmd->args still holds the original.
                free(exe_path); // TODO: causing double free if we free it here, since os_spawn_process uses it.
            }
        }

        // --- Cleanup for this command's FDs in the parent ---

        // If input_fd_for_current_cmd was a pipe from a previous command, close it now.
        // The current command (or its child) has either used it or had it replaced by file redirection.
        if (input_fd_for_current_cmd != shell_original_stdin) {
            os_close_fd(input_fd_for_current_cmd);
        }

        // If current_cmd_stdout was the write end of a pipe (pipe_fds[1]), close it.
        // The child process inherited this FD and will use it (or it was replaced by file redir).
        // The parent doesn't need it anymore.
        if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) {
            os_close_fd(pipe_fds[1]);
            pipe_fds[1] = -1; // Mark as closed
        } else if (pipe_fds[1] != -1 && current_cmd_stdout != pipe_fds[1]) {
            // This means current_cmd_stdout was redirected to a file,
            // but a pipe was created. The write end of that unused pipe must be closed.
            os_close_fd(pipe_fds[1]);
            pipe_fds[1] = -1;
        }


        // The read end of the pipe (pipe_fds[0], which is next_input_fd_temp)
        // becomes the input_fd_for_current_cmd for the *next* iteration.
        // If output was redirected to a file, next_input_fd_temp would be -1.
        if (!is_last_cmd) {
            if (redirection_error || (cmd->builtin_idx != -1 && cmd->exit_status !=0) || (cmd->builtin_idx == -1 && cmd->pid == OS_INVALID_PID && cmd->exit_status !=0) ) {
                 // If current command had an error that prevented it from writing to the pipe
                 // or if it was a builtin that errored, the next command should get EOF.
                 // If next_input_fd_temp is still valid (pipe_fds[0]), it will naturally provide EOF
                 // because the write end (pipe_fds[1]) would have been closed or not written to.
            }
            input_fd_for_current_cmd = next_input_fd_temp;
            if (input_fd_for_current_cmd == -1 ) { // Pipe was closed due to output redirection earlier
                // Create a dummy pipe that's immediately closed on write end, so next cmd reads EOF.
                int dummy_pipe[2];
                if(os_create_pipe(&dummy_pipe[0], &dummy_pipe[1])) {
                    os_close_fd(dummy_pipe[1]); // Close write end immediately
                    input_fd_for_current_cmd = dummy_pipe[0]; // Next command reads EOF
                } else {
                    // Fallback if dummy pipe fails: use original stdin, though less ideal.
                    // Or, better, signal an error. For now, let it try original stdin.
                    input_fd_for_current_cmd = shell_original_stdin; // Or os_dup(shell_original_stdin) if it might be closed
                    // Actually, shell_original_stdin is always open, so direct assignment is okay.
                }
            }
        }
    } // End of for loop iterating through commands in pipeline

    // Wait for all child processes in the pipeline
    for (int i = 0; i < num_cmds; i++) {
        CommandSegment *cmd = &pipeline->segments[i];
        if (cmd->pid != OS_INVALID_PID && cmd->builtin_idx == -1) { // If it was an external command
            int status;
            if (os_wait_for_process(cmd->pid, &status) == 0) {
                cmd->exit_status = status;
            } else {
                // Error waiting, e.g., process doesn't exist or permission issue
                // This shouldn't happen if os_spawn_process succeeded.
                cmd->exit_status = 255; // General error
                perror("execute_pipeline: os_wait_for_process");
            }
            last_cmd_status = cmd->exit_status; // The exit status of the last command in pipeline determines overall status
        } else if (cmd->arg_count > 0 || cmd->input_file || cmd->output_file_stdout || cmd->output_file_stderr) {
            // For builtins or commands that were just redirections, their status was set during execution.
            last_cmd_status = cmd->exit_status;
        }
        // If a command was empty and skipped, its status is implicitly 0 from initialization
        // or set if it was only redirections.
    }

cleanup_and_exit_pipeline:
    // Restore original stdio for the shell
    if (os_dup2(shell_original_stdin, OS_STDIN_FD) == -1) perror("os_dup2 restore STDIN_FILENO");
    if (os_dup2(shell_original_stdout, OS_STDOUT_FD) == -1) perror("os_dup2 restore STDOUT_FILENO");
    if (os_dup2(shell_original_stderr, OS_STDERR_FD) == -1) perror("os_dup2 restore STDERR_FILENO");

    os_close_fd(shell_original_stdin);
    os_close_fd(shell_original_stdout);
    os_close_fd(shell_original_stderr);

    return last_cmd_status;
}


// --- Builtin Implementations ---
int builtin_echo(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("%s", argv[i]);
        if (i < argc - 1) {
            printf(" ");
        }
    }
    printf("\n");
    return 0;
}

int builtin_exit_shell(int argc, char **argv) {
    int exit_code = 0;
    bool valid_arg = true;

    if (argc > 1) {
        char *first_arg = argv[1];
        char *end_ptr;
        long val = strtol(first_arg, &end_ptr, 10);

        if (first_arg == end_ptr || *end_ptr != '\0') {
            fprintf(stderr, "bash: exit: %s: numeric argument required\n", first_arg);
            exit_code = 2; // Or 255, common for such errors.
            valid_arg = false;
        } else {
            exit_code = (int)(val & 0xFF); // Exit status is 8-bit
        }

        if (argc > 2 && valid_arg) {
            fprintf(stderr, "bash: exit: too many arguments\n");
            return 1; // Bash doesn't exit, returns error
        }
    }
    // If !valid_arg, bash exits with the error code (e.g. 2 for numeric arg required)
    // If valid_arg and argc > 2, it doesn't exit.

    da_free(&current_completion_matches, true); // Cleanup completion data
    os_cleanup_line_input(); // Cleanup readline/history
    exit(exit_code); // Exit the shell process
    return 0; // Should not be reached
}


int builtin_type(int argc, char **argv) {
    if (argc < 2) {
        // fprintf(stderr, "type: usage: type [-afpt] name [name ...]\n"); // Original has options
        fprintf(stderr, "type: usage: type name [name ...]\n");
        return 1;
    }
    int overall_ret_val = 0;
    for (int k = 1; k < argc; ++k) {
        char *cmd_name = argv[k];
        if (strlen(cmd_name) == 0) {
            printf("%s: not found\n", cmd_name); // Bash behavior for `type ""`
            overall_ret_val = 1;
            continue;
        }

        bool found = false;
        // 1. Check builtins
        for (int i = 0; BUILTIN_COMMAND_TABLE[i].name != NULL; i++) {
            if (strcmp(cmd_name, BUILTIN_COMMAND_TABLE[i].name) == 0) {
                printf("%s is a shell builtin\n", cmd_name);
                found = true;
                break;
            }
        }
        if (found) continue;

        // 2. Check executables in PATH
        char *exe_loc = os_find_executable_in_path(cmd_name); // Use OSAL
        if (exe_loc != NULL) {
            printf("%s is %s\n", cmd_name, exe_loc);
            free(exe_loc); // Remember to free result from os_find_executable_in_path
        } else {
            printf("%s: not found\n", cmd_name);
            overall_ret_val = 1; // If any are not found, return non-zero
        }
    }
    return overall_ret_val;
}

int builtin_pwd(int argc, char **argv) {
    char cwd_buf[FULL_PATH_BUFFER_SIZE]; // Or use PATH_MAX
    if (os_get_current_dir(cwd_buf, sizeof(cwd_buf)) != NULL) { // Use OSAL
        printf("%s\n", cwd_buf);
    } else {
        fprintf(stderr, "pwd: %s\n", os_get_last_error_string()); // Use OSAL error
        return 1;
    }
    return 0;
}

int builtin_cd(int argc, char **argv) {
    char target_path_buf[FULL_PATH_BUFFER_SIZE];
    const char *path_to_change_to = NULL;
    char *allocated_path_to_change_to = NULL; // For constructed paths like ~/foo

    const char *original_arg_for_error = NULL;


    if (argc > 2) {
        fprintf(stderr, "cd: too many arguments\n");
        return 1;
    }

    if (argc == 1) { // "cd" or "cd ~" (implicitly)
        original_arg_for_error = "~"; // For error messages
        allocated_path_to_change_to = os_get_env("HOME");
        if (!allocated_path_to_change_to || strlen(allocated_path_to_change_to) == 0) {
            fprintf(stderr, "cd: HOME not set\n");
            if(allocated_path_to_change_to) free(allocated_path_to_change_to);
            return 1;
        }
        path_to_change_to = allocated_path_to_change_to;
    } else { // argc == 2, "cd <arg>"
        original_arg_for_error = argv[1];
        if (strcmp(argv[1], "~") == 0) {
            allocated_path_to_change_to = os_get_env("HOME");
            if (!allocated_path_to_change_to || strlen(allocated_path_to_change_to) == 0) {
                fprintf(stderr, "cd: HOME not set\n");
                if(allocated_path_to_change_to) free(allocated_path_to_change_to);
                return 1;
            }
            path_to_change_to = allocated_path_to_change_to;
        } else if (strncmp(argv[1], "~/", 2) == 0) {
            char *home_dir = os_get_env("HOME");
            if (!home_dir || strlen(home_dir) == 0) {
                fprintf(stderr, "cd: HOME not set\n");
                if(home_dir) free(home_dir);
                return 1;
            }
            // Ensure buffer is large enough: strlen(home) + strlen(argv[1]+1 for '/') + 1 for null
            size_t needed_size = strlen(home_dir) + strlen(argv[1] + 1) + 1; // +1 for potential extra '/'
            if (needed_size > sizeof(target_path_buf)){
                 fprintf(stderr, "cd: path too long\n");
                 free(home_dir);
                 return 1;
            }

            if (strcmp(home_dir, "/") == 0) { // HOME is root, avoid `//`
                 snprintf(target_path_buf, sizeof(target_path_buf), "/%s", argv[1] + 2);
            } else {
                 snprintf(target_path_buf, sizeof(target_path_buf), "%s/%s", home_dir, argv[1] + 2);
            }
            free(home_dir);
            path_to_change_to = target_path_buf; // Points to stack buffer
        } else if (strcmp(argv[1], "-") == 0) {
            allocated_path_to_change_to = os_get_env("OLDPWD");
            if (!allocated_path_to_change_to) {
                fprintf(stderr, "cd: OLDPWD not set\n");
                return 1;
            }
            path_to_change_to = allocated_path_to_change_to;
            printf("%s\n", path_to_change_to); // "cd -" prints the directory
        } else if (strlen(argv[1]) == 0) { // "cd """
             path_to_change_to = argv[1]; // which is ""
        } else {
            path_to_change_to = argv[1]; // Direct path
        }
    }

    if (path_to_change_to == NULL ) { // Should only happen if logic error above or HOME/OLDPWD getenv failed and wasn't argv[1]
        fprintf(stderr, "cd: %s: No such file or directory\n", original_arg_for_error ? original_arg_for_error : "target");
        if (allocated_path_to_change_to) free(allocated_path_to_change_to);
        return 1;
    }


    char old_pwd_buf[FULL_PATH_BUFFER_SIZE];
    bool old_pwd_set = false;
    if (os_get_current_dir(old_pwd_buf, sizeof(old_pwd_buf)) != NULL) {
        old_pwd_set = true;
    }

    if (os_change_dir(path_to_change_to) != 0) { // Use OSAL
        fprintf(stderr, "cd: %s: %s\n", original_arg_for_error ? original_arg_for_error : path_to_change_to, os_get_last_error_string());
        if (allocated_path_to_change_to) free(allocated_path_to_change_to);
        return 1;
    } else {
        if(old_pwd_set) {
            if (os_set_env("OLDPWD", old_pwd_buf, 1) != 0) { // Use OSAL
                fprintf(stderr, "cd: setenv OLDPWD failed: %s\n", os_get_last_error_string());
            }
        }
        char new_pwd_buf[FULL_PATH_BUFFER_SIZE];
        if (os_get_current_dir(new_pwd_buf, sizeof(new_pwd_buf)) != NULL) {
             if (os_set_env("PWD", new_pwd_buf, 1) != 0) { // Use OSAL
                fprintf(stderr, "cd: setenv PWD failed: %s\n", os_get_last_error_string());
            }
        } else {
            fprintf(stderr, "cd: getcwd after chdir failed: %s\n", os_get_last_error_string());
        }
    }

    if (allocated_path_to_change_to) free(allocated_path_to_change_to);
    return 0;
}

int builtin_history(int argc, char **argv) {
    int history_len = os_get_history_length();
    int history_start_base = os_get_history_base();

    if (history_len == 0) {
        return 0; // No history to show
    }

    int num_to_show = history_len; // Default to show all

    if (argc > 1) {
        char *endptr;
        long count = strtol(argv[1], &endptr, 10);
        if (*endptr == '\0' && argv[1] != endptr) { // Successfully parsed an integer
            if (count >= 0) { // Non-negative count
                 num_to_show = (int)count;
                 if (num_to_show > history_len) num_to_show = history_len; // Cap at actual length
            }
            // Negative or invalid number: default to showing all (or handle error as per desired shell behavior)
        }
        // Non-numeric argument: default to showing all (or error)
    }
    if (argc > 2) {
        fprintf(stderr, "history: too many arguments\n"); // Bash behavior
        return 1; // Bash returns 1
    }


    int first_entry_idx_in_list = 0; // This is 0-based index into the conceptual history list
    if (num_to_show < history_len) {
        first_entry_idx_in_list = history_len - num_to_show;
    }

    for (int i = 0; i < num_to_show; i++) {
        int list_idx = first_entry_idx_in_list + i;
        int display_num = history_start_base + list_idx;

        char* line = os_get_history_entry_line(display_num); // Use display num (1-based if base is 1)
        if (line) {
            printf("%5d  %s\n", display_num, line);
            free(line);
        }
    }
    return 0;
}


// --- Input Parsing (remains mostly the same, no direct OS calls) ---
char **parse_input(const char *input_line_const, int *arg_count) {
    *arg_count = 0;
    if (input_line_const == NULL) return NULL;

    // Max possible arguments is MAX_ARGS. Add 1 for the NULL terminator.
    char **args = malloc((MAX_ARGS + 1) * sizeof(char *));
    if (!args) { perror("malloc for args array"); return NULL; }

    char token_buffer[MAX_INPUT_LENGTH + 1]; // Buffer for current token
    int token_pos = 0;
    int current_arg_idx = 0;
    const char *ptr = input_line_const;
    bool in_single_quotes = false;
    bool in_double_quotes = false;
    bool just_exited_quotes = false; // To help with "" or '' being actual arguments


    while (*ptr && current_arg_idx < MAX_ARGS) {
        // Skip leading whitespace before a token (unless in quotes)
        while (*ptr && isspace((unsigned char)*ptr) && !in_single_quotes && !in_double_quotes) {
            ptr++;
        }
        if (!*ptr) break; // End of input line

        token_pos = 0;           // Reset token buffer position
        bool token_started_by_quote = false; // Was this token initiated by a quote? (for empty strings)
        bool current_segment_had_content = false; // Did current quote/non-quote segment add chars?

        // Loop to build one token
        while (*ptr) {
            char current_char = *ptr;
            just_exited_quotes = false;

            if (in_single_quotes) {
                if (current_char == '\'') {
                    in_single_quotes = false;
                    just_exited_quotes = true;
                    ptr++; // Consume the closing quote
                } else {
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    current_segment_had_content = true;
                    ptr++;
                }
            } else if (in_double_quotes) {
                if (current_char == '"') {
                    in_double_quotes = false;
                    just_exited_quotes = true;
                    ptr++; // Consume the closing quote
                } else if (current_char == '\\' && (*(ptr+1) == '"' || *(ptr+1) == '\\' || *(ptr+1) == '$' || *(ptr+1) == '`')) {
                    ptr++; // Consume backslash
                    if (*ptr && token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = *ptr;
                    current_segment_had_content = true;
                    if (*ptr) ptr++;
                } else {
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    current_segment_had_content = true;
                    ptr++;
                }
            } else { // Not in any quotes
                if (isspace((unsigned char)current_char)) {
                    break; // End of token (space encountered)
                } else if (current_char == '\'') {
                    in_single_quotes = true;
                    if (token_pos == 0) token_started_by_quote = true; // Token starts with a quote
                    current_segment_had_content = false; // Reset for this new segment
                    ptr++;
                } else if (current_char == '"') {
                    in_double_quotes = true;
                    if (token_pos == 0) token_started_by_quote = true;
                    current_segment_had_content = false;
                    ptr++;
                } else if (current_char == '\\') {
                    ptr++; // Consume backslash
                    if (*ptr) { // If there's a character after backslash
                        if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = *ptr;
                        current_segment_had_content = true;
                        ptr++;
                    } // If backslash is at end of line, it might be line continuation (not handled here)
                } else { // Regular character
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    current_segment_had_content = true;
                    ptr++;
                }
            }
             // If we just exited quotes, and the next char is not a space,
             // it means the token continues (e.g., "hello"world or 'hello'world).
             // If next char IS a space, or end of line, or another quote, the current token part might end.
            if (just_exited_quotes) {
                if (!*ptr || isspace((unsigned char)*ptr) || *ptr == '\'' || *ptr == '"') {
                    // If after exiting quotes, it's whitespace or EOL or another quote, the segment ends.
                    // The outer loop will handle adding the token if it has content.
                    // Or if it's another quote, the next iteration of this inner loop will handle it.
                    break;
                }
                // else: next char is part of the same token, e.g. "a"b -> ab. Continue inner loop.
            }
            // If we are not in quotes and current_segment_had_content is false (e.g. after processing a quote pair)
            // and the next char is a space or EOL, then this token segment is done.
            if (!in_single_quotes && !in_double_quotes && !current_segment_had_content && (!*ptr || isspace((unsigned char)*ptr))) {
                 // This can happen if we had `""` then a space.
                 // The token (empty string) should have been added.
                 break;
            }
        } // End of inner while loop (building one token)

        // Add the token if it has content OR if it was started by a quote (e.g. "" or '')
        if (token_pos > 0 || token_started_by_quote) {
            token_buffer[token_pos] = '\0';
            args[current_arg_idx] = strdup(token_buffer);
            if (!args[current_arg_idx]) {
                perror("strdup for token in parse_input");
                for (int i = 0; i < current_arg_idx; i++) free(args[i]);
                free(args); *arg_count = 0; return NULL;
            }
            current_arg_idx++;
        }

        // If quotes are still open at the end of the line, it's a syntax error (or multi-line input, not handled)
        // For simplicity, we treat unclosed quotes as an error for this parser version.
        // The problem is, if `*ptr` is null here, the outer loop terminates.
        // We need to check `in_single_quotes` or `in_double_quotes` *after* the outer loop if `*ptr` is null.
        // For now, this parser assumes quotes are closed on the same line or it's an unterminated token.
    } // End of outer while loop (iterating through input_line_const)

    if (in_single_quotes || in_double_quotes) {
        // Unterminated quote error
        fprintf(stderr, "bash: syntax error: unterminated quoted string\n");
        // Free already parsed args and return error
        for (int i = 0; i < current_arg_idx; i++) free(args[i]);
        free(args);
        *arg_count = 0;
        return NULL;
    }


    args[current_arg_idx] = NULL; // Null-terminate the argument array
    *arg_count = current_arg_idx;
    return args;
}


void free_parsed_args(char **args) {
    if (!args) return;
    for (int i = 0; args[i] != NULL; i++) {
        free(args[i]);
    }
    free(args);
}

// --- Main Function ---
int main(int argc_main, char *argv_main[]) {
    os_initialize_line_input(); // Uses OSAL
    os_initialize_history_system(); // Uses OSAL

    os_set_completion_handler(shell_completion_func); // Use OSAL to register our handler
    os_set_completion_append_character(' ');         // Use OSAL

    da_init(&current_completion_matches, 0); // Initialize global for completion generator

    char *line_buffer_from_os;
    while((line_buffer_from_os = os_read_line("$ ")) != NULL) { // Use OSAL
        if (line_buffer_from_os[0] != '\0') {
            os_add_to_history(line_buffer_from_os); // Use OSAL
        }

        // Trim leading and trailing whitespace from the line
        char *trimmed_line = line_buffer_from_os;
        while (*trimmed_line && isspace((unsigned char)*trimmed_line)) trimmed_line++;

        char *end_of_line = trimmed_line + strlen(trimmed_line);
        while (end_of_line > trimmed_line && isspace((unsigned char)*(end_of_line - 1))) {
            end_of_line--;
        }
        *end_of_line = '\0';

        if (strlen(trimmed_line) == 0) { // Empty line after trimming
            free(line_buffer_from_os); // Free memory from os_read_line
            continue;
        }

        Pipeline *pipeline = parse_line_into_pipeline(trimmed_line);

        if (pipeline) {
            if (pipeline->num_segments > 0) {
                execute_pipeline(pipeline);
            }
            free_pipeline_resources(pipeline);
        } else {
            // parse_line_into_pipeline might print syntax errors itself
        }
        free(line_buffer_from_os); // Free memory from os_read_line
    }

    // EOF reached (e.g., Ctrl+D)
    if (line_buffer_from_os == NULL) {
        if (os_is_tty(OS_STDIN_FD)) { // Check if input is a terminal
            printf("\n"); // Print newline like bash on exit via Ctrl+D
        }
    }

    da_free(&current_completion_matches, true);
    os_cleanup_line_input(); // Use OSAL (clears history for readline)

    return 0;
}