#include <stdio.h>
#include <stdlib.h>   // For exit(), strtol(), getenv(), free(), EXIT_FAILURE, qsort, atexit()
#include <string.h>   // For strlen, strcspn, strcmp, strncmp, strtok, strdup(), strndup
#include <ctype.h>    // For isspace()
#include <unistd.h>   // For access(), X_OK, fork(), execv(), chdir(), dup, dup2, close, STDOUT_FILENO, STDERR_FILENO, pipe()
#include <sys/wait.h> // For waitpid()
#include <sys/stat.h> // For stat(), S_ISDIR()
#include <errno.h>    // For errno and strerror()
#include <stdbool.h>  // For bool type
#include <fcntl.h>    // For open() and O_* flags
#include <readline/readline.h>
#include <readline/history.h> // Required for history features
#include <dirent.h>   // For opendir, readdir, closedir

#define MAX_INPUT_LENGTH 256
#define FULL_PATH_BUFFER_SIZE 1024
#define MAX_ARGS 64
#define MAX_PIPELINE_SEGMENTS 16

// Forward declarations
int builtin_echo(int argc, char **argv);
int builtin_exit_shell(int argc, char **argv);
int builtin_type(int argc, char **argv);
int builtin_pwd(int argc, char **argv);
int builtin_cd(int argc, char **argv);
int builtin_history(int argc, char **argv);

char **parse_input(const char *input_line_const, int *arg_count);
void free_parsed_args(char **args);

// --- Structures for Pipeline (forward declare Pipeline for free_pipeline_resources) ---
typedef struct Pipeline Pipeline; // <<< Forward declaration of struct Pipeline
void free_pipeline_resources(Pipeline *pipeline); // <<< ADDED: Forward declaration

typedef int (*builtin_handler_func)(int argc, char **argv);

typedef struct {
    const char *name;
    builtin_handler_func handler;
} BuiltinCommandEntry;

BuiltinCommandEntry BUILTIN_COMMAND_TABLE[];


typedef struct {
    char **elements;
    int count;
    int capacity;
} DynamicArray;

void da_init(DynamicArray *da, int initial_capacity) {
    da->elements = malloc(initial_capacity * sizeof(char*));
    if (!da->elements && initial_capacity > 0) {
        perror("malloc for dynamic array elements");
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
            if (element) free(element);
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
            if (j != i) { // If the unique element isn't already in its sorted unique place
                da->elements[j] = da->elements[i]; // Move it
            }
        } else {
            free(da->elements[i]); // It's a duplicate, free it
            da->elements[i] = NULL; // Mark as NULL
        }
    }
    da->count = j + 1;
    // Optionally, reallocate to shrink if many duplicates were removed.
    // For now, `da->count` correctly reflects the number of unique, non-NULL elements at the start.
}


static DynamicArray current_completion_matches;
static int current_completion_idx;
static int last_history_sync_index = 0;

char* command_generator_func(const char* text, int state);
char** shell_completion_func(const char* text_line_buffer, int start_index, int end_index);

char* command_generator_func(const char* text, int state) {
    if (state == 0) {
        da_free(&current_completion_matches, true);
        da_init(&current_completion_matches, 10);
        current_completion_idx = 0;

        for (int i = 0; BUILTIN_COMMAND_TABLE[i].name != NULL; i++) {
            if (strncmp(BUILTIN_COMMAND_TABLE[i].name, text, strlen(text)) == 0) {
                da_add(&current_completion_matches, strdup(BUILTIN_COMMAND_TABLE[i].name));
            }
        }

        char *path_env_full = getenv("PATH");
        if (path_env_full) {
            char *path_env_copy = strdup(path_env_full);
            if (path_env_copy) {
                char *path_dir = strtok(path_env_copy, ":");
                while (path_dir) {
                    DIR *d = opendir(path_dir);
                    if (d) {
                        struct dirent *entry;
                        while ((entry = readdir(d)) != NULL) {
                            if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
                                continue;
                            }
                            if (strncmp(entry->d_name, text, strlen(text)) == 0) {
                                char full_exe_path[FULL_PATH_BUFFER_SIZE];
                                snprintf(full_exe_path, sizeof(full_exe_path), "%s/%s", path_dir, entry->d_name);
                                if (access(full_exe_path, X_OK) == 0) {
                                    struct stat st;
                                    if (stat(full_exe_path, &st) == 0 && !S_ISDIR(st.st_mode)) {
                                         da_add(&current_completion_matches, strdup(entry->d_name));
                                    }
                                }
                            }
                        }
                        closedir(d);
                    }
                    path_dir = strtok(NULL, ":");
                }
                free(path_env_copy);
            }
        }
        da_sort(&current_completion_matches); 
        da_unique(&current_completion_matches); 
    }

    if (current_completion_idx < current_completion_matches.count) {
        return strdup(current_completion_matches.elements[current_completion_idx++]); 
    }

    return NULL;
}

char** shell_completion_func(const char* text_line_buffer, int start_index, int end_index) {
    rl_attempted_completion_over = 1;

    bool first_word_completion = true;
    for (int i = 0; i < start_index; i++) {
        if (!isspace(text_line_buffer[i])) {
            first_word_completion = false;
            break;
        }
    }

    if (!first_word_completion) {
        rl_attempted_completion_over = 0; 
        return NULL;
    }

    char *word_to_complete = strndup(text_line_buffer + start_index, end_index - start_index);
    if (!word_to_complete) {
        return NULL;
    }

    char **matches = rl_completion_matches(word_to_complete, command_generator_func);
    free(word_to_complete);
    return matches;
}


typedef struct {
    char **args;
    int arg_count;
    char *input_file;
    char *output_file_stdout;
    bool append_stdout;
    char *output_file_stderr;
    bool append_stderr;
    int builtin_idx;
    pid_t pid;
    int exit_status;
} CommandSegment;

// Actual struct definition for Pipeline
struct Pipeline {
    CommandSegment segments[MAX_PIPELINE_SEGMENTS];
    int num_segments;
};


char *find_executable_in_path(const char *command_name) {
    if (command_name == NULL || strlen(command_name) == 0) return NULL;
    if (strchr(command_name, '/') != NULL) {
        if (access(command_name, X_OK) == 0) {
            char* path = strdup(command_name);
            if (!path) { perror("strdup for direct path"); return NULL; }
            struct stat st;
            if (stat(path, &st) == 0 && !S_ISDIR(st.st_mode)) { 
                 return path;
            }
            free(path); 
        }
        return NULL;
    }
    char *path_env_original = getenv("PATH");
    if (path_env_original == NULL) return NULL;
    char *path_env_copy = strdup(path_env_original);
    if (path_env_copy == NULL) { perror("strdup for PATH"); return NULL; }
    char full_executable_path_buffer[FULL_PATH_BUFFER_SIZE];
    char *found_path_str = NULL;
    char *dir_token = strtok(path_env_copy, ":");
    while (dir_token != NULL) {
        if (strlen(dir_token) > 0) {
            snprintf(full_executable_path_buffer, sizeof(full_executable_path_buffer), "%s/%s", dir_token, command_name);
            if (access(full_executable_path_buffer, X_OK) == 0) {
                 struct stat st;
                 if (stat(full_executable_path_buffer, &st) == 0 && !S_ISDIR(st.st_mode)) { 
                    found_path_str = strdup(full_executable_path_buffer);
                    if (found_path_str == NULL) perror("strdup for found_path_str");
                    break;
                }
            }
        }
        dir_token = strtok(NULL, ":");
    }
    free(path_env_copy);
    return found_path_str;
}

void parse_single_segment(const char *segment_str, CommandSegment *cmd_seg) {
    memset(cmd_seg, 0, sizeof(CommandSegment));
    cmd_seg->builtin_idx = -1;

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

    while (current_token_idx < num_segment_tokens) {
        char *token = segment_tokens[current_token_idx];
        if (strcmp(token, "<") == 0 || strcmp(token, ">") == 0 || strcmp(token, ">>") == 0 ||
            strcmp(token, "2>") == 0 || strcmp(token, "2>>") == 0 ||
            strcmp(token, "1>") == 0 || strcmp(token, "1>>") == 0) {
            break;
        }
        cmd_seg->args[cmd_seg->arg_count++] = strdup(token);
        if (!cmd_seg->args[cmd_seg->arg_count -1]) {
            perror("strdup for command argument");
            syntax_error = true; break;
        }
        current_token_idx++;
    }
    cmd_seg->args[cmd_seg->arg_count] = NULL;

    while (current_token_idx < num_segment_tokens && !syntax_error) {
        char *op_token = segment_tokens[current_token_idx++];
        if (current_token_idx >= num_segment_tokens) {
            fprintf(stderr, "bash: syntax error near unexpected token `newline'\n");
            syntax_error = true; break;
        }
        char *filename_token = segment_tokens[current_token_idx++];

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
            fprintf(stderr, "bash: syntax error near unexpected token `%s'\n", op_token);
            syntax_error = true;
        }
        if (syntax_error) break;
    }

    free_parsed_args(segment_tokens);

    if (syntax_error) {
        if (cmd_seg->args) {
            for (int i = 0; cmd_seg->args[i] != NULL; i++) free(cmd_seg->args[i]);
            free(cmd_seg->args);
            cmd_seg->args = NULL;
        }
        cmd_seg->arg_count = 0;
        if (cmd_seg->input_file) { free(cmd_seg->input_file); cmd_seg->input_file = NULL; }
        if (cmd_seg->output_file_stdout) { free(cmd_seg->output_file_stdout); cmd_seg->output_file_stdout = NULL; }
        if (cmd_seg->output_file_stderr) { free(cmd_seg->output_file_stderr); cmd_seg->output_file_stderr = NULL; }
        cmd_seg->builtin_idx = -2; 
        return;
    }

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
            *next_pipe_char = '\0';
        }

        char *start = current_segment_str;
        while (*start && isspace((unsigned char)*start)) start++;

        char *end = start + strlen(start) - 1;
        while (end >= start && isspace((unsigned char)*end)) end--;
        *(end + 1) = '\0';

        if (strlen(start) == 0) { 
            if ( (pipeline->num_segments == 0 && next_pipe_char) || 
                 (pipeline->num_segments > 0 && next_pipe_char) || 
                 (current_segment_str == line_copy && next_pipe_char && strlen(next_pipe_char + 1) == 0 && strlen(start)==0) || // " | "
                 (next_pipe_char && !*(next_pipe_char +1) && strlen(start)==0) // "cmd | " (empty segment after pipe)
                ) {
                // Check if it is truly an empty segment that's problematic
                // "cmd | " -> next_pipe_char points to |, *start is empty.
                // " | cmd" -> current_segment_str points to line_copy, *start empty, next_pipe_char exists
                // "cmd1 | | cmd2" -> first iter "cmd1", second iter *start empty, next_pipe_char exists
                if (next_pipe_char) { // An actual pipe character was involved with this empty segment
                    fprintf(stderr, "bash: syntax error near unexpected token `|'\n");
                    syntax_error_in_pipeline = true;
                    break;
                }
            }
        }

        if (strlen(start) > 0) {
             parse_single_segment(start, &pipeline->segments[pipeline->num_segments]);
             if (pipeline->segments[pipeline->num_segments].builtin_idx == -2) { 
                 syntax_error_in_pipeline = true;
                 break;
             }
             pipeline->num_segments++;
        }


        if (next_pipe_char) {
            current_segment_str = next_pipe_char + 1;
            if (pipeline->num_segments == MAX_PIPELINE_SEGMENTS && strchr(current_segment_str, '|')) {
                 fprintf(stderr, "bash: too many pipe segments\n"); 
                 syntax_error_in_pipeline = true; 
                 break;
            }
        } else {
            break;
        }
    }

    free(line_copy);
    if (syntax_error_in_pipeline || pipeline->num_segments == 0) {
        free_pipeline_resources(pipeline); 
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
    }
    free(pipeline);
}

int execute_pipeline(Pipeline *pipeline) {
    if (!pipeline || pipeline->num_segments == 0) return 0;

    int num_cmds = pipeline->num_segments;
    int last_cmd_status = 0;

    int shell_original_stdin = dup(STDIN_FILENO);
    int shell_original_stdout = dup(STDOUT_FILENO);
    int shell_original_stderr = dup(STDERR_FILENO);
    if (shell_original_stdin == -1 || shell_original_stdout == -1 || shell_original_stderr == -1) {
        perror("dup original shell stdio");
        if(shell_original_stdin != -1) close(shell_original_stdin);
        if(shell_original_stdout != -1) close(shell_original_stdout);
        if(shell_original_stderr != -1) close(shell_original_stderr);
        return 255; 
    }

    int input_fd_for_current_cmd = shell_original_stdin;
    int pipe_fds[2] = {-1, -1};

    for (int i = 0; i < num_cmds; i++) {
        CommandSegment *cmd = &pipeline->segments[i];
        bool is_last_cmd = (i == num_cmds - 1);

        int current_cmd_stdin = input_fd_for_current_cmd;
        int current_cmd_stdout = shell_original_stdout;
        int current_cmd_stderr = shell_original_stderr;

        int next_input_fd_temp = -1; 

        if (!is_last_cmd) {
            if (pipe(pipe_fds) == -1) {
                perror("pipe");
                last_cmd_status = 1; 
                if (input_fd_for_current_cmd != shell_original_stdin) close(input_fd_for_current_cmd);
                goto cleanup_and_exit_pipeline;
            }
            current_cmd_stdout = pipe_fds[1]; 
            next_input_fd_temp = pipe_fds[0]; 
        }

        int user_redirect_in_fd = -1;
        int user_redirect_out_fd = -1;
        int user_redirect_err_fd = -1;
        bool redirection_error = false;

        if (cmd->input_file) {
            user_redirect_in_fd = open(cmd->input_file, O_RDONLY);
            if (user_redirect_in_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->input_file, strerror(errno));
                redirection_error = true; cmd->exit_status = 1;
            } else {
                if (current_cmd_stdin != shell_original_stdin && current_cmd_stdin != input_fd_for_current_cmd) close(current_cmd_stdin);
                else if (current_cmd_stdin == input_fd_for_current_cmd && input_fd_for_current_cmd != shell_original_stdin) { /* This is a pipe fd, will be closed later or by child */ }
                current_cmd_stdin = user_redirect_in_fd;
            }
        }
        if (!redirection_error && cmd->output_file_stdout) {
            int flags = O_WRONLY | O_CREAT | (cmd->append_stdout ? O_APPEND : O_TRUNC);
            user_redirect_out_fd = open(cmd->output_file_stdout, flags, 0666);
            if (user_redirect_out_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->output_file_stdout, strerror(errno));
                redirection_error = true; cmd->exit_status = 1;
            } else {
                if (current_cmd_stdout != shell_original_stdout && current_cmd_stdout != pipe_fds[1]) close(current_cmd_stdout);
                else if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) { /* This is a pipe fd, will be closed later or by child */ }
                current_cmd_stdout = user_redirect_out_fd;
                if (next_input_fd_temp != -1 && next_input_fd_temp == pipe_fds[0]) { 
                    close(next_input_fd_temp); 
                    next_input_fd_temp = -1; 
                    pipe_fds[0] = -1; // Mark the pipe's read end as dealt with
                }
            }
        }
        if (!redirection_error && cmd->output_file_stderr) {
            int flags = O_WRONLY | O_CREAT | (cmd->append_stderr ? O_APPEND : O_TRUNC);
            user_redirect_err_fd = open(cmd->output_file_stderr, flags, 0666);
            if (user_redirect_err_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->output_file_stderr, strerror(errno));
                redirection_error = true; cmd->exit_status = 1;
            } else {
                if (current_cmd_stderr != shell_original_stderr) close(current_cmd_stderr); 
                current_cmd_stderr = user_redirect_err_fd;
            }
        }

        if (redirection_error) {
            last_cmd_status = cmd->exit_status;
            // Close any FDs that were successfully opened for redirection before the error
            if (user_redirect_in_fd != -1 && current_cmd_stdin != user_redirect_in_fd) close(user_redirect_in_fd); // Only if not assigned
            if (user_redirect_out_fd != -1 && current_cmd_stdout != user_redirect_out_fd) close(user_redirect_out_fd);
            if (user_redirect_err_fd != -1 && current_cmd_stderr != user_redirect_err_fd) close(user_redirect_err_fd);
            
            // If this command was supposed to write to a pipe, that pipe is now broken for the next command.
            // Close the write end if it was assigned.
            if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) {
                close(pipe_fds[1]); pipe_fds[1] = -1;
            }
            // The read end (next_input_fd_temp / pipe_fds[0]) will be handled by parent_fd_management.
            // If it's still open, the next command will read EOF.
        } else if (cmd->arg_count == 0 && !(cmd->input_file || cmd->output_file_stdout || cmd->output_file_stderr)) {
             cmd->exit_status = 0; last_cmd_status = 0;
        } else if (cmd->arg_count == 0) { 
            cmd->exit_status = 0; last_cmd_status = 0;
        } else if (cmd->builtin_idx != -1) {
            int temp_stdin_dup = dup(STDIN_FILENO);
            int temp_stdout_dup = dup(STDOUT_FILENO);
            int temp_stderr_dup = dup(STDERR_FILENO);

            if (dup2(current_cmd_stdin, STDIN_FILENO) == -1) perror("dup2 stdin for builtin");
            if (dup2(current_cmd_stdout, STDOUT_FILENO) == -1) perror("dup2 stdout for builtin");
            if (dup2(current_cmd_stderr, STDERR_FILENO) == -1) perror("dup2 stderr for builtin");

            // Close the FDs that were duped, if they are not the original shell FDs or input_fd_for_current_cmd (pipe from prev)
            if (current_cmd_stdin != shell_original_stdin && current_cmd_stdin != input_fd_for_current_cmd) close(current_cmd_stdin);
            if (current_cmd_stdout != shell_original_stdout && current_cmd_stdout != (pipe_fds[1] == -1 ? -2 : pipe_fds[1])) close(current_cmd_stdout); // -2 to ensure not equal if pipe_fds[1] is -1
            if (current_cmd_stderr != shell_original_stderr) close(current_cmd_stderr);

            cmd->exit_status = BUILTIN_COMMAND_TABLE[cmd->builtin_idx].handler(cmd->arg_count, cmd->args);
            last_cmd_status = cmd->exit_status;
            fflush(stdout);
            fflush(stderr);

            dup2(temp_stdin_dup, STDIN_FILENO); close(temp_stdin_dup);
            dup2(temp_stdout_dup, STDOUT_FILENO); close(temp_stdout_dup);
            dup2(temp_stderr_dup, STDERR_FILENO); close(temp_stderr_dup);

        } else {
            char* exe_path = find_executable_in_path(cmd->args[0]);
            if (!exe_path) {
                fprintf(stderr, "%s: command not found\n", cmd->args[0]);
                cmd->exit_status = 127; last_cmd_status = 127;
            } else {
                cmd->pid = fork();
                if (cmd->pid == -1) {
                    perror("fork"); free(exe_path); cmd->exit_status = 1; last_cmd_status = 1;
                } else if (cmd->pid == 0) {
                    if (current_cmd_stdin != STDIN_FILENO) { if(dup2(current_cmd_stdin, STDIN_FILENO)==-1) { perror("child dup2 stdin"); exit(126); } close(current_cmd_stdin); }
                    if (current_cmd_stdout != STDOUT_FILENO) { if(dup2(current_cmd_stdout, STDOUT_FILENO)==-1) { perror("child dup2 stdout"); exit(126); } close(current_cmd_stdout); }
                    if (current_cmd_stderr != STDERR_FILENO) { if(dup2(current_cmd_stderr, STDERR_FILENO)==-1) { perror("child dup2 stderr"); exit(126); } close(current_cmd_stderr); }

                    close(shell_original_stdin); close(shell_original_stdout); close(shell_original_stderr);
                    if (input_fd_for_current_cmd != current_cmd_stdin && input_fd_for_current_cmd != shell_original_stdin) close(input_fd_for_current_cmd);

                    if (!is_last_cmd && next_input_fd_temp != -1 && next_input_fd_temp == pipe_fds[0]) { 
                        close(next_input_fd_temp); 
                    }
                    // Close original user redirection FDs if they were different from what was duped
                    // (they should have been closed when current_cmd_std* was assigned if different)
                    // The FDs current_cmd_std* themselves are closed after dup2.

                    execv(exe_path, cmd->args);
                    fprintf(stderr, "%s: %s\n", cmd->args[0], strerror(errno));
                    free(exe_path); exit(errno == ENOENT ? 127 : 126); // 127 for not found, 126 for other exec errors
                }
                free(exe_path);
            }
        }
        // last_cmd_status updated inside blocks for builtins/external for immediate effect on next loop if needed.
        // For external commands, waitpid later will set final status. This `last_cmd_status` is more like a "provisional" one.

    // parent_fd_management:
        if (input_fd_for_current_cmd != shell_original_stdin) {
            close(input_fd_for_current_cmd);
        }
        // Close user redirect FDs that were specifically assigned to current_cmd_std*
        // No, these are closed by child/builtin logic or were never current_cmd_std*.
        // Parent closes pipe ends it's done with.
        if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) { 
            close(pipe_fds[1]); 
            pipe_fds[1] = -1;
        } else if (pipe_fds[1] != -1 && current_cmd_stdout != pipe_fds[1]) {
            // stdout was redirected to a file, but a pipe was created. Close unused write end.
            close(pipe_fds[1]);
            pipe_fds[1] = -1;
        }


        if (!is_last_cmd) {
            if (redirection_error || (cmd->builtin_idx != -1 && cmd->exit_status !=0) || (cmd->builtin_idx == -1 && cmd->pid ==0 && cmd->exit_status !=0) ) {
                // If current command failed and was supposed to feed a pipe
                if (next_input_fd_temp != -1 && next_input_fd_temp == pipe_fds[0]) {
                    // The write end (pipe_fds[1]) should have been closed or not used.
                    // The read end (pipe_fds[0] / next_input_fd_temp) will give EOF.
                }
            }
            input_fd_for_current_cmd = next_input_fd_temp;
            if (input_fd_for_current_cmd == -1 ) { // Pipe was closed due to output redirection
                // Create a closed pipe for the next command to read EOF from
                int dummy_pipe[2];
                if(pipe(dummy_pipe) == 0) {
                    close(dummy_pipe[1]); // Close write end immediately
                    input_fd_for_current_cmd = dummy_pipe[0]; // Next command reads EOF
                } else {
                    // Fallback, though pipe creation failure is serious
                    input_fd_for_current_cmd = shell_original_stdin;
                }
            }
        }
    }

    for (int i = 0; i < num_cmds; i++) {
        CommandSegment *cmd = &pipeline->segments[i];
        if (cmd->pid > 0) {
            int status;
            waitpid(cmd->pid, &status, 0);
            if (WIFEXITED(status)) cmd->exit_status = WEXITSTATUS(status);
            else if (WIFSIGNALED(status)) cmd->exit_status = 128 + WTERMSIG(status);
            last_cmd_status = cmd->exit_status;
        } else if (cmd->arg_count > 0 || cmd->input_file || cmd->output_file_stdout || cmd->output_file_stderr) {
            // Builtin, command not found, or redirection-only
            last_cmd_status = cmd->exit_status;
        }
        // If it's an empty command segment that parser let through, its status would be 0.
    }

cleanup_and_exit_pipeline:
    dup2(shell_original_stdin, STDIN_FILENO);
    dup2(shell_original_stdout, STDOUT_FILENO);
    dup2(shell_original_stderr, STDERR_FILENO);

    close(shell_original_stdin);
    close(shell_original_stdout);
    close(shell_original_stderr);

    return last_cmd_status;
}


int builtin_echo(int argc, char **argv) {
    for (int i = 1; i < argc; i++) { printf("%s", argv[i]); if (i < argc - 1) printf(" "); }
    printf("\n"); return 0;
}
int builtin_exit_shell(int argc, char **argv) {
    int exit_code = 0; // Default exit code
    bool valid_arg = true;

    if (argc > 1) {
        char *first_arg = argv[1];
        char *end_ptr;
        long val = strtol(first_arg, &end_ptr, 10);

        if (first_arg == end_ptr || *end_ptr != '\0') { // Not a valid number or has trailing chars
            fprintf(stderr, "bash: exit: %s: numeric argument required\n", first_arg);
            exit_code = 2; // Common for such errors in bash, or 255
            valid_arg = false;
        } else {
            exit_code = (int)(val & 0xFF); // Only care about the lower 8 bits for exit status
        }

        if (argc > 2 && valid_arg) { // Valid numeric first arg, but more args given
            fprintf(stderr, "bash: exit: too many arguments\n");
            return 1; // Bash doesn't exit in this case, returns error
        }
    }
    
    // The atexit handler will now manage saving history and freeing resources.
    exit(exit_code);
    return 0; // Should not be reached
}

int builtin_type(int argc, char **argv) {
    if (argc < 2) {
        // "type" with no args is not an error in bash, it does nothing and returns 0.
        // However, the test "type_multiple_args.sh" expects "usage: type..." for "type" alone.
        // Reverting to original error for compliance with that specific test if it exists.
        // If the test is about `type cmd1 cmd2`, then no-arg case is less critical.
        // For now, let's assume no args means "do nothing, return 0" like bash.
        // BUT the prompt example shows: "type: usage: type [-afpt] name [name ...]"
        // So, stick to that.
        fprintf(stderr, "type: usage: type [-afpt] name [name ...]\n"); return 1;
    }
    int ret_val = 0;
    for (int k=1; k<argc; ++k) {
        char *cmd_name = argv[k];
        if (strlen(cmd_name) == 0) { printf("%s: not found\n", cmd_name); ret_val =1; continue; } 
        bool found = false;
        for (int i = 0; BUILTIN_COMMAND_TABLE[i].name != NULL; i++) {
            if (strcmp(cmd_name, BUILTIN_COMMAND_TABLE[i].name) == 0) {
                printf("%s is a shell builtin\n", cmd_name); found=true; break;
            }
        }
        if (found) continue;
        char *exe_loc = find_executable_in_path(cmd_name);
        if (exe_loc != NULL) { printf("%s is %s\n", cmd_name, exe_loc); free(exe_loc); }
        else { printf("%s: not found\n", cmd_name); ret_val = 1; }
    }
    return ret_val;
}
int builtin_pwd(int argc, char **argv) {
    char cwd_buf[FULL_PATH_BUFFER_SIZE];
    if (getcwd(cwd_buf, sizeof(cwd_buf)) != NULL) printf("%s\n", cwd_buf);
    else { perror("pwd"); return 1; }
    return 0;
}
int builtin_cd(int argc, char **argv) {
    char target_path_buf[FULL_PATH_BUFFER_SIZE];
    const char *path_to_use_const = NULL;
    char *path_to_use_dynamic = NULL;

    const char *original_arg_for_error = NULL;

    if (argc > 2) {
        fprintf(stderr, "cd: too many arguments\n"); return 1;
    }

    if (argc == 1) { // "cd"
        original_arg_for_error = "~"; // For error message if HOME not set
        path_to_use_const = getenv("HOME");
        if (path_to_use_const == NULL || strlen(path_to_use_const) == 0) { // Treat empty HOME as not set for cd
            fprintf(stderr, "cd: HOME not set\n"); return 1;
        }
    } else { // argc == 2, "cd <arg>"
        original_arg_for_error = argv[1];
        if (strcmp(argv[1], "~") == 0) {
            path_to_use_const = getenv("HOME");
            if (path_to_use_const == NULL || strlen(path_to_use_const) == 0) {
                fprintf(stderr, "cd: HOME not set\n"); return 1;
            }
        } else if (strncmp(argv[1], "~/", 2) == 0) {
            const char *home_dir = getenv("HOME");
            if (home_dir == NULL || strlen(home_dir) == 0) {
                fprintf(stderr, "cd: HOME not set\n"); return 1;
            }
            if (strcmp(home_dir, "/") == 0) { // HOME is root
                 snprintf(target_path_buf, sizeof(target_path_buf), "/%s", argv[1] + 2);
            } else {
                 snprintf(target_path_buf, sizeof(target_path_buf), "%s/%s", home_dir, argv[1] + 2);
            }
            path_to_use_dynamic = target_path_buf;
        } else if (strcmp(argv[1], "-") == 0) {
            path_to_use_const = getenv("OLDPWD");
            if (path_to_use_const == NULL) {
                fprintf(stderr, "cd: OLDPWD not set\n"); return 1;
            }
            printf("%s\n", path_to_use_const);
        } else if (strlen(argv[1]) == 0) { // "cd """
             // Let chdir handle empty path string, it should fail.
             // original_arg_for_error is already ""
             path_to_use_const = argv[1]; // which is ""
        }
        else {
            path_to_use_const = argv[1];
        }
    }

    char *effective_path = path_to_use_dynamic ? path_to_use_dynamic : (char*)path_to_use_const;

    if (effective_path == NULL ) { // Should only happen if getenv failed and wasn't argv[1]
        fprintf(stderr, "cd: %s: No such file or directory\n", original_arg_for_error);
        return 1;
    }
    // Note: an empty `effective_path` (e.g. from `cd ""`) will be passed to chdir.
    // `chdir("")` typically fails with ENOENT.

    char old_pwd_buf[FULL_PATH_BUFFER_SIZE];
    bool old_pwd_set = false;
    if (getcwd(old_pwd_buf, sizeof(old_pwd_buf)) != NULL) {
        old_pwd_set = true;
    }


    if (chdir(effective_path) != 0) {
        fprintf(stderr, "cd: %s: %s\n", original_arg_for_error, strerror(errno));
        return 1;
    } else {
        if(old_pwd_set) {
            if (setenv("OLDPWD", old_pwd_buf, 1) != 0) {
                perror("cd: setenv OLDPWD failed");
            }
        }
        char new_pwd_buf[FULL_PATH_BUFFER_SIZE];
        if (getcwd(new_pwd_buf, sizeof(new_pwd_buf)) != NULL) {
             if (setenv("PWD", new_pwd_buf, 1) != 0) {
                perror("cd: setenv PWD failed");
            }
        } else {
            perror("cd: getcwd after chdir failed");
        }
    }
    return 0;
}


char **parse_input(const char *input_line_const, int *arg_count) {
    *arg_count = 0;
    if (input_line_const == NULL) return NULL;

    char **args = malloc((MAX_ARGS + 1) * sizeof(char *));
    if (!args) { perror("malloc for args array"); return NULL; }

    char token_buffer[MAX_INPUT_LENGTH + 1]; 
    int token_pos = 0;
    int current_arg_idx = 0;
    const char *ptr = input_line_const;
    bool in_single_quotes = false;
    bool in_double_quotes = false;
    bool just_exited_quotes = false;


    while (*ptr && current_arg_idx < MAX_ARGS) {
        // Skip leading whitespace for a new token
        while (*ptr && isspace((unsigned char)*ptr) && !in_single_quotes && !in_double_quotes) {
            ptr++;
        }
        if (!*ptr) break;

        token_pos = 0;
        bool token_started = false;
        just_exited_quotes = false;

        // Consume one token
        while (*ptr) {
            char current_char = *ptr;
            just_exited_quotes = false;

            if (in_single_quotes) {
                if (current_char == '\'') {
                    in_single_quotes = false;
                    just_exited_quotes = true; 
                    ptr++;
                } else {
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    ptr++;
                }
            } else if (in_double_quotes) {
                if (current_char == '"') {
                    in_double_quotes = false;
                    just_exited_quotes = true;
                    ptr++;
                } else if (current_char == '\\' && (*(ptr+1) == '"' || *(ptr+1) == '\\' || *(ptr+1) == '$' || *(ptr+1) == '`')) {
                    ptr++; // consume backslash
                    if (*ptr && token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = *ptr;
                    if (*ptr) ptr++;
                } else {
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    ptr++;
                }
            } else { // Not in any quotes
                if (isspace((unsigned char)current_char)) {
                    break; // End of token
                } else if (current_char == '\'') {
                    in_single_quotes = true;
                    token_started = true; // A quote starts a token if not already started
                    ptr++;
                } else if (current_char == '"') {
                    in_double_quotes = true;
                    token_started = true;
                    ptr++;
                } else if (current_char == '\\') {
                    ptr++; // consume backslash
                    if (*ptr) { // If there's a character after backslash
                        if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = *ptr;
                        token_started = true;
                        ptr++;
                    } else { // Trailing backslash (bash usually ignores, or error in some contexts)
                        // For simplicity, treat as literal if at EOL, or let it be part of token if followed by space
                        // if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = '\\';
                        // token_started = true;
                        break; // End of input, backslash might be start of next line in interactive
                    }
                } else { // Regular character
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    token_started = true;
                    ptr++;
                }
            }
             if (!token_started && token_pos > 0) token_started = true; // If we added to buffer
             if (just_exited_quotes && *ptr && !isspace((unsigned char)*ptr) && *ptr != '\'' && *ptr != '"') {
                // e.g. echo 'foo'bar -> foobar. Continue token.
                // No break here, loop continues.
             } else if (just_exited_quotes) {
                // e.g. echo 'foo' bar or echo 'foo'"bar"
                // if next is space, token ends. if next is quote, new quote segment starts.
                // if next is end of line, token ends.
                // The main loop structure handles this: if space follows, it breaks outer loop.
             }

        } // End of inner while (*ptr) for current token

        if (token_pos > 0 || token_started) { // Add token if it has content or quotes were involved
            token_buffer[token_pos] = '\0';
            args[current_arg_idx] = strdup(token_buffer);
            if (!args[current_arg_idx]) {
                perror("strdup for token in parse_input");
                for (int i = 0; i < current_arg_idx; i++) free(args[i]);
                free(args); *arg_count = 0; return NULL;
            }
            current_arg_idx++;
        }
         if (in_single_quotes || in_double_quotes) { // Unterminated quotes
            // fprintf(stderr, "bash: unexpected EOF while looking for matching quote\n");
            // Add what was parsed so far as a token
            if(token_pos > 0){
                token_buffer[token_pos] = '\0';
                args[current_arg_idx] = strdup(token_buffer);
                if (!args[current_arg_idx]) { /* error handling */ } else {current_arg_idx++;}
            }
            break; // Stop parsing further
        }

    } // End of outer while (*ptr && current_arg_idx < MAX_ARGS)

    args[current_arg_idx] = NULL;
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

int builtin_history(int argc, char **argv) {
    extern int history_length;

    // Handle 'history -r <filename>'
    if (argc > 1 && strcmp(argv[1], "-r") == 0) {
        if (argc < 3) {
            fprintf(stderr, "bash: history: -r: option requires an argument\n");
            return 1;
        }
        if (argc > 3) {
            fprintf(stderr, "bash: history: too many arguments\n");
            return 1;
        }
        
        char *filename = argv[2];
        if (read_history(filename) != 0) {
            fprintf(stderr, "bash: history: %s: %s\n", filename, strerror(errno));
            return 1;
        }
        last_history_sync_index = history_length;
        return 0;
    }

    // Handle 'history -w <filename>'
    if (argc > 1 && strcmp(argv[1], "-w") == 0) {
        if (argc < 3) {
            fprintf(stderr, "bash: history: -w: option requires an argument\n");
            return 1;
        }
        if (argc > 3) {
            fprintf(stderr, "bash: history: too many arguments\n");
            return 1;
        }
        
        char *filename = argv[2];
        if (write_history(filename) != 0) {
            fprintf(stderr, "bash: history: %s: %s\n", filename, strerror(errno));
            return 1;
        }
        last_history_sync_index = history_length;
        return 0;
    }

    // Handle 'history -a <filename>'
    if (argc > 1 && strcmp(argv[1], "-a") == 0) {
        if (argc < 3) {
            fprintf(stderr, "bash: history: -a: option requires an argument\n");
            return 1;
        }
        if (argc > 3) {
            fprintf(stderr, "bash: history: too many arguments\n");
            return 1;
        }
        
        char *filename = argv[2];
        int num_to_append = history_length - last_history_sync_index;

        if (num_to_append > 0) {
            if (append_history(num_to_append, filename) != 0) {
                fprintf(stderr, "bash: history: %s: %s\n", filename, strerror(errno));
                return 1;
            }
        }
        
        last_history_sync_index = history_length;
        return 0;
    }

    // Handle 'history [n]' and other argument validation
    if (argc > 1 && (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "-w") == 0 || strcmp(argv[1], "-a") == 0)) {
        // This case is already handled above, but as a safeguard.
    } else if (argc > 2) {
        fprintf(stderr, "bash: history: too many arguments\n");
        return 1;
    }

    extern int history_base;
    HIST_ENTRY **the_list = history_list();

    if (!the_list) {
        return 0;
    }

    int num_to_show = history_length; 

    if (argc == 2) {
        char *endptr;
        long count = strtol(argv[1], &endptr, 10);
        if (*endptr == '\0' && argv[1] != endptr) {
            if (count >= 0) {
                 num_to_show = (int)count;
            }
        }
    }

    int first_entry_to_print_idx = 0; 
    if (num_to_show < history_length) {
        first_entry_to_print_idx = history_length - num_to_show;
    }
    
    for (int i = first_entry_to_print_idx; i < history_length; i++) {
        if (the_list[i] && the_list[i]->line) {
            printf("%5d  %s\n", history_base + i, the_list[i]->line);
        }
    }
    return 0;
}


BuiltinCommandEntry BUILTIN_COMMAND_TABLE[] = {
    {"echo", builtin_echo}, {"exit", builtin_exit_shell}, {"type", builtin_type},
    {"pwd", builtin_pwd}, {"cd", builtin_cd},
    {"history", builtin_history}, 
    {NULL, NULL}
};

void cleanup_on_exit(void) {
    char *histfile = getenv("HISTFILE");
    if (histfile && *histfile) {
        // Overwrite the history file with the current in-memory history
        write_history(histfile); 
    }
    da_free(&current_completion_matches, true);
    // rl_clear_history() frees memory used by the history list.
    // It is generally good practice to call it.
    rl_clear_history();
}

int main(int argc_main, char *argv_main[]) {
    // Ensure readline linkage for tests that might not use stdin directly
    rl_readline_version; 
    setbuf(stdout, NULL); setbuf(stderr, NULL);
    
    // Register the cleanup function to be called on normal exit.
    atexit(cleanup_on_exit);

    using_history();
    
    // Load history from HISTFILE on startup
    char *histfile = getenv("HISTFILE");
    if (histfile && *histfile) {
        // read_history returns 0 on success
        if (read_history(histfile) == 0) {
            // After loading, sync the index to the new length
            extern int history_length;
            last_history_sync_index = history_length;
        }
    }

    rl_attempted_completion_function = shell_completion_func;
    rl_completion_append_character = ' ';
    da_init(&current_completion_matches, 0);

    char *line_buffer_from_readline;
    while((line_buffer_from_readline = readline("$ ")) != NULL) {
        if (line_buffer_from_readline[0] != '\0') {
            add_history(line_buffer_from_readline);
        }

        char *trimmed_line = line_buffer_from_readline;
        while (*trimmed_line && isspace((unsigned char)*trimmed_line)) trimmed_line++;

        char *end_of_line = trimmed_line + strlen(trimmed_line); 
        while (end_of_line > trimmed_line && isspace((unsigned char)*(end_of_line - 1))) {
            end_of_line--;
        }
        *end_of_line = '\0';

        if (strlen(trimmed_line) == 0) {
            free(line_buffer_from_readline);
            continue;
        }

        Pipeline *pipeline = parse_line_into_pipeline(trimmed_line);

        if (pipeline) {
            if (pipeline->num_segments > 0) {
                execute_pipeline(pipeline);
            }
            free_pipeline_resources(pipeline);
        }
        free(line_buffer_from_readline);
    }

    if (line_buffer_from_readline == NULL) { 
        if (isatty(STDIN_FILENO)) {
            printf("\n");
        }
    }
    // All cleanup is now handled by the atexit handler.
    return 0;
}
