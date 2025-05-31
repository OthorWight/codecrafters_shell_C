#include "os_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_INPUT_LENGTH 256
#define FULL_PATH_BUFFER_SIZE 4096
#define MAX_ARGS 64
#define MAX_PIPELINE_SEGMENTS 16

int builtin_echo(int argc, char **argv);
int builtin_exit_shell(int argc, char **argv);
int builtin_type(int argc, char **argv);
int builtin_pwd(int argc, char **argv);
int builtin_cd(int argc, char **argv);
int builtin_history(int argc, char **argv);

char **parse_input(const char *input_line_const, int *arg_count);
void free_parsed_args(char **args);

typedef struct Pipeline Pipeline;
void free_pipeline_resources(Pipeline *pipeline);

typedef int (*builtin_handler_func)(int argc, char **argv);

typedef struct {
    const char *name;
    builtin_handler_func handler;
} BuiltinCommandEntry;

BuiltinCommandEntry BUILTIN_COMMAND_TABLE[] = {
    {"echo", builtin_echo}, {"exit", builtin_exit_shell}, {"type", builtin_type},
    {"pwd", builtin_pwd}, {"cd", builtin_cd},
    {"history", builtin_history},
    {NULL, NULL}
};

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
static DynamicArray current_completion_matches;
static int current_completion_idx;

char* command_generator_func(const char* text, int state) {
    if (state == 0) {
        da_free(&current_completion_matches, true);
        da_init(&current_completion_matches, 10);
        current_completion_idx = 0;

        for (int i = 0; BUILTIN_COMMAND_TABLE[i].name != NULL; i++) {
            if (strncmp(BUILTIN_COMMAND_TABLE[i].name, text, strlen(text)) == 0) {
                char* match = strdup(BUILTIN_COMMAND_TABLE[i].name);
                if (match) da_add(&current_completion_matches, match);
            }
        }

        char *path_env_full = os_get_env("PATH");
        if (path_env_full) {
            char *path_env_copy = strdup(path_env_full);
            if (path_env_copy) {
                char path_sep_str[2] = {os_get_path_separator_char(), '\0'};
                char *path_dir = strtok(path_env_copy, path_sep_str);
                while (path_dir) {
                    os_dir_t d = os_open_dir(path_dir);
                    if (d) {
                        os_dir_entry_t entry;
                        while (os_read_dir_entry(d, &entry)) {

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
                                    if (content_len >= sizeof(full_exe_path)) {

                                        continue; 
                                    }
                                    snprintf(full_exe_path, sizeof(full_exe_path), "%s%s", path_dir, entry.name);
                                } else {
                                    content_len = path_dir_len + 1 + entry_name_len;
                                    if (content_len >= sizeof(full_exe_path)) {

                                        continue; 
                                    }

                                    #pragma GCC diagnostic push
                                    #pragma GCC diagnostic ignored "-Wformat-truncation"
                                    snprintf(full_exe_path, sizeof(full_exe_path), "%s/%s", path_dir, entry.name);
                                    #pragma GCC diagnostic pop
                                }

                                if (os_file_exists_and_is_accessible(full_exe_path, true)) {
                                    if (!os_is_directory(full_exe_path)) {
                                         char* match = strdup(entry.name);
                                         if (match) da_add(&current_completion_matches, match);
                                    }
                                }
                            }
                        }
                        os_close_dir(d);
                    }
                    path_dir = strtok(NULL, path_sep_str);
                }
                free(path_env_copy);
            }
            free(path_env_full);
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
    os_attempted_completion_over = 1;

    bool first_word_completion = true;
    for (int i = 0; i < start_index; i++) {
        if (!isspace((unsigned char)text_line_buffer[i])) {
            first_word_completion = false;
            break;
        }
    }

    if (!first_word_completion) {

        os_attempted_completion_over = 0;
        return NULL;
    }

    char *word_to_complete = strndup(text_line_buffer + start_index, end_index - start_index);
    if (!word_to_complete) {
        return NULL;
    }

    char **matches = os_perform_completion_matches(word_to_complete, command_generator_func);
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
    int builtin_idx;
    os_pid_t pid;
    int exit_status;
} CommandSegment;

struct Pipeline {
    CommandSegment segments[MAX_PIPELINE_SEGMENTS];
    int num_segments;
};

char *local_find_executable_in_path(const char *command_name) {
    return os_find_executable_in_path(command_name);
}

void parse_single_segment(const char *segment_str, CommandSegment *cmd_seg) {
    memset(cmd_seg, 0, sizeof(CommandSegment));
    cmd_seg->builtin_idx = -1;
    cmd_seg->pid = OS_INVALID_PID;

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
                 (current_segment_str == line_copy && next_pipe_char && strlen(next_pipe_char + 1) == 0 && strlen(start)==0) ||
                 (next_pipe_char && !*(next_pipe_char +1) && strlen(start)==0)
                ) {
                if (next_pipe_char) {
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

    int shell_original_stdin = os_dup(OS_STDIN_FD);
    int shell_original_stdout = os_dup(OS_STDOUT_FD);
    int shell_original_stderr = os_dup(OS_STDERR_FD);

    if (shell_original_stdin == -1 || shell_original_stdout == -1 || shell_original_stderr == -1) {
        perror("execute_pipeline: os_dup original shell stdio");
        if(shell_original_stdin != -1) os_close_fd(shell_original_stdin);
        if(shell_original_stdout != -1) os_close_fd(shell_original_stdout);
        if(shell_original_stderr != -1) os_close_fd(shell_original_stderr);
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
            if (!os_create_pipe(&pipe_fds[0], &pipe_fds[1])) {
                perror("execute_pipeline: os_create_pipe");
                last_cmd_status = 1;

                if (input_fd_for_current_cmd != shell_original_stdin) os_close_fd(input_fd_for_current_cmd);
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
            user_redirect_in_fd = os_open_file(cmd->input_file, OS_OPEN_READONLY, 0);
            if (user_redirect_in_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->input_file, os_get_last_error_string());
                redirection_error = true; cmd->exit_status = 1;
            } else {

                if (current_cmd_stdin != shell_original_stdin && current_cmd_stdin != input_fd_for_current_cmd) {
                     os_close_fd(current_cmd_stdin);
                } else if (current_cmd_stdin == input_fd_for_current_cmd && input_fd_for_current_cmd != shell_original_stdin) {

                }
                current_cmd_stdin = user_redirect_in_fd;
            }
        }

        if (!redirection_error && cmd->output_file_stdout) {
            int flags = OS_OPEN_WRITEONLY | OS_OPEN_CREATE | (cmd->append_stdout ? OS_OPEN_APPEND : OS_OPEN_TRUNCATE);
            user_redirect_out_fd = os_open_file(cmd->output_file_stdout, flags, OS_DEFAULT_FILE_PERMS);
            if (user_redirect_out_fd == -1) {
                fprintf(stderr, "bash: %s: %s\n", cmd->output_file_stdout, os_get_last_error_string());
                redirection_error = true; cmd->exit_status = 1;
            } else {

                if (current_cmd_stdout != shell_original_stdout && current_cmd_stdout != pipe_fds[1]) {
                     os_close_fd(current_cmd_stdout);
                } else if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) {

                }
                current_cmd_stdout = user_redirect_out_fd;
                if (next_input_fd_temp != -1 && next_input_fd_temp == pipe_fds[0]) {

                    os_close_fd(next_input_fd_temp);
                    next_input_fd_temp = -1;
                    if (pipe_fds[0] != -1) pipe_fds[0] = -1;
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
                if (current_cmd_stderr != shell_original_stderr) os_close_fd(current_cmd_stderr);
                current_cmd_stderr = user_redirect_err_fd;
            }
        }

        if (redirection_error) {
            last_cmd_status = cmd->exit_status;

            if (user_redirect_in_fd != -1 && current_cmd_stdin != user_redirect_in_fd) os_close_fd(user_redirect_in_fd);
            if (user_redirect_out_fd != -1 && current_cmd_stdout != user_redirect_out_fd) os_close_fd(user_redirect_out_fd);
            if (user_redirect_err_fd != -1 && current_cmd_stderr != user_redirect_err_fd) os_close_fd(user_redirect_err_fd);

            if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) {
                os_close_fd(pipe_fds[1]); pipe_fds[1] = -1;
            }

        } else if (cmd->arg_count == 0 && !(cmd->input_file || cmd->output_file_stdout || cmd->output_file_stderr)) {

             cmd->exit_status = 0; last_cmd_status = 0;

        } else if (cmd->arg_count == 0) {
            cmd->exit_status = 0; last_cmd_status = 0;
        } else if (cmd->builtin_idx != -1) {
            int temp_stdin_dup = os_dup(OS_STDIN_FD);
            int temp_stdout_dup = os_dup(OS_STDOUT_FD);
            int temp_stderr_dup = os_dup(OS_STDERR_FD);

            if (os_dup2(current_cmd_stdin, OS_STDIN_FD) == -1) perror("os_dup2 stdin for builtin");
            if (os_dup2(current_cmd_stdout, OS_STDOUT_FD) == -1) perror("os_dup2 stdout for builtin");
            if (os_dup2(current_cmd_stderr, OS_STDERR_FD) == -1) perror("os_dup2 stderr for builtin");

            if (current_cmd_stdin != shell_original_stdin && current_cmd_stdin != input_fd_for_current_cmd) os_close_fd(current_cmd_stdin);
            if (current_cmd_stdout != shell_original_stdout && current_cmd_stdout != (pipe_fds[1] == -1 ? -2 : pipe_fds[1])) os_close_fd(current_cmd_stdout);
            if (current_cmd_stderr != shell_original_stderr) os_close_fd(current_cmd_stderr);

            cmd->exit_status = BUILTIN_COMMAND_TABLE[cmd->builtin_idx].handler(cmd->arg_count, cmd->args);
            last_cmd_status = cmd->exit_status;
            fflush(stdout);
            fflush(stderr);

            os_dup2(temp_stdin_dup, OS_STDIN_FD); os_close_fd(temp_stdin_dup);
            os_dup2(temp_stdout_dup, OS_STDOUT_FD); os_close_fd(temp_stdout_dup);
            os_dup2(temp_stderr_dup, OS_STDERR_FD); os_close_fd(temp_stderr_dup);

        } else {
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
                    child_argv[0] = exe_path;
                    for (int j = 0; j < cmd->arg_count; j++) {
                        child_argv[j + 1] = cmd->args[j];
                    }
                    child_argv[cmd->arg_count] = NULL;
    
                    os_process_start_info_t start_info = {0};
                    start_info.argv = child_argv;
                    start_info.argv[0] = exe_path;
                    start_info.stdin_fd = current_cmd_stdin;
                    start_info.stdout_fd = current_cmd_stdout;
                    start_info.stderr_fd = current_cmd_stderr;

                    cmd->pid = os_spawn_process(&start_info);

                    if (cmd->pid == OS_INVALID_PID) {
                        perror("execute_pipeline: os_spawn_process");
                        cmd->exit_status = 1; last_cmd_status = 1;
                    }
                    free(child_argv);
                }

                free(exe_path);
            }
        }

        // --- Cleanup for this command's FDs in the parent ---

        if (input_fd_for_current_cmd != shell_original_stdin) {
            os_close_fd(input_fd_for_current_cmd);
        }

        if (current_cmd_stdout == pipe_fds[1] && pipe_fds[1] != -1) {
            os_close_fd(pipe_fds[1]);
            pipe_fds[1] = -1;
        } else if (pipe_fds[1] != -1 && current_cmd_stdout != pipe_fds[1]) {

            os_close_fd(pipe_fds[1]);
            pipe_fds[1] = -1;
        }

        if (!is_last_cmd) {
            if (redirection_error || (cmd->builtin_idx != -1 && cmd->exit_status !=0) || (cmd->builtin_idx == -1 && cmd->pid == OS_INVALID_PID && cmd->exit_status !=0) ) {

            }
            input_fd_for_current_cmd = next_input_fd_temp;
            if (input_fd_for_current_cmd == -1 ) {

                int dummy_pipe[2];
                if(os_create_pipe(&dummy_pipe[0], &dummy_pipe[1])) {
                    os_close_fd(dummy_pipe[1]);
                    input_fd_for_current_cmd = dummy_pipe[0];
                } else {

                    input_fd_for_current_cmd = shell_original_stdin;

                }
            }
        }
    }

    for (int i = 0; i < num_cmds; i++) {
        CommandSegment *cmd = &pipeline->segments[i];
        if (cmd->pid != OS_INVALID_PID && cmd->builtin_idx == -1) {
            int status;
            if (os_wait_for_process(cmd->pid, &status) == 0) {
                cmd->exit_status = status;
            } else {

                cmd->exit_status = 255;
                perror("execute_pipeline: os_wait_for_process");
            }
            last_cmd_status = cmd->exit_status;
        } else if (cmd->arg_count > 0 || cmd->input_file || cmd->output_file_stdout || cmd->output_file_stderr) {

            last_cmd_status = cmd->exit_status;
        }

    }

cleanup_and_exit_pipeline:

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
            exit_code = 2;
            valid_arg = false;
        } else {
            exit_code = (int)(val & 0xFF);
        }

        if (argc > 2 && valid_arg) {
            fprintf(stderr, "bash: exit: too many arguments\n");
            return 1;
        }
    }

    da_free(&current_completion_matches, true);
    os_cleanup_line_input();
    exit(exit_code);
    return 0;
}

int builtin_type(int argc, char **argv) {
    if (argc < 2) {

        fprintf(stderr, "type: usage: type name [name ...]\n");
        return 1;
    }
    int overall_ret_val = 0;
    for (int k = 1; k < argc; ++k) {
        char *cmd_name = argv[k];
        if (strlen(cmd_name) == 0) {
            printf("%s: not found\n", cmd_name);
            overall_ret_val = 1;
            continue;
        }

        bool found = false;

        for (int i = 0; BUILTIN_COMMAND_TABLE[i].name != NULL; i++) {
            if (strcmp(cmd_name, BUILTIN_COMMAND_TABLE[i].name) == 0) {
                printf("%s is a shell builtin\n", cmd_name);
                found = true;
                break;
            }
        }
        if (found) continue;

        char *exe_loc = os_find_executable_in_path(cmd_name);
        if (exe_loc != NULL) {
            printf("%s is %s\n", cmd_name, exe_loc);
            free(exe_loc);
        } else {
            printf("%s: not found\n", cmd_name);
            overall_ret_val = 1;
        }
    }
    return overall_ret_val;
}

int builtin_pwd(int argc, char **argv) {
    char cwd_buf[FULL_PATH_BUFFER_SIZE];
    if (os_get_current_dir(cwd_buf, sizeof(cwd_buf)) != NULL) {
        printf("%s\n", cwd_buf);
    } else {
        fprintf(stderr, "pwd: %s\n", os_get_last_error_string());
        return 1;
    }
    return 0;
}

int builtin_cd(int argc, char **argv) {
    char target_path_buf[FULL_PATH_BUFFER_SIZE];
    const char *path_to_change_to = NULL;
    char *allocated_path_to_change_to = NULL;

    const char *original_arg_for_error = NULL;

    if (argc > 2) {
        fprintf(stderr, "cd: too many arguments\n");
        return 1;
    }

    if (argc == 1) {
        original_arg_for_error = "~";
        allocated_path_to_change_to = os_get_env("HOME");
        if (!allocated_path_to_change_to || strlen(allocated_path_to_change_to) == 0) {
            fprintf(stderr, "cd: HOME not set\n");
            if(allocated_path_to_change_to) free(allocated_path_to_change_to);
            return 1;
        }
        path_to_change_to = allocated_path_to_change_to;
    } else {
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

            size_t needed_size = strlen(home_dir) + strlen(argv[1] + 1) + 1;
            if (needed_size > sizeof(target_path_buf)){
                 fprintf(stderr, "cd: path too long\n");
                 free(home_dir);
                 return 1;
            }

            if (strcmp(home_dir, "/") == 0) {
                 snprintf(target_path_buf, sizeof(target_path_buf), "/%s", argv[1] + 2);
            } else {
                 snprintf(target_path_buf, sizeof(target_path_buf), "%s/%s", home_dir, argv[1] + 2);
            }
            free(home_dir);
            path_to_change_to = target_path_buf;
        } else if (strcmp(argv[1], "-") == 0) {
            allocated_path_to_change_to = os_get_env("OLDPWD");
            if (!allocated_path_to_change_to) {
                fprintf(stderr, "cd: OLDPWD not set\n");
                return 1;
            }
            path_to_change_to = allocated_path_to_change_to;
            printf("%s\n", path_to_change_to);
        } else if (strlen(argv[1]) == 0) {
             path_to_change_to = argv[1];
        } else {
            path_to_change_to = argv[1];
        }
    }

    if (path_to_change_to == NULL ) {
        fprintf(stderr, "cd: %s: No such file or directory\n", original_arg_for_error ? original_arg_for_error : "target");
        if (allocated_path_to_change_to) free(allocated_path_to_change_to);
        return 1;
    }

    char old_pwd_buf[FULL_PATH_BUFFER_SIZE];
    bool old_pwd_set = false;
    if (os_get_current_dir(old_pwd_buf, sizeof(old_pwd_buf)) != NULL) {
        old_pwd_set = true;
    }

    if (os_change_dir(path_to_change_to) != 0) {
        fprintf(stderr, "cd: %s: %s\n", original_arg_for_error ? original_arg_for_error : path_to_change_to, os_get_last_error_string());
        if (allocated_path_to_change_to) free(allocated_path_to_change_to);
        return 1;
    } else {
        if(old_pwd_set) {
            if (os_set_env("OLDPWD", old_pwd_buf, 1) != 0) {
                fprintf(stderr, "cd: setenv OLDPWD failed: %s\n", os_get_last_error_string());
            }
        }
        char new_pwd_buf[FULL_PATH_BUFFER_SIZE];
        if (os_get_current_dir(new_pwd_buf, sizeof(new_pwd_buf)) != NULL) {
             if (os_set_env("PWD", new_pwd_buf, 1) != 0) {
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
        return 0;
    }

    int num_to_show = history_len;

    if (argc > 1) {
        char *endptr;
        long count = strtol(argv[1], &endptr, 10);
        if (*endptr == '\0' && argv[1] != endptr) {
            if (count >= 0) {
                 num_to_show = (int)count;
                 if (num_to_show > history_len) num_to_show = history_len;
            }

        }

    }
    if (argc > 2) {
        fprintf(stderr, "history: too many arguments\n");
        return 1;
    }

    int first_entry_idx_in_list = 0;
    if (num_to_show < history_len) {
        first_entry_idx_in_list = history_len - num_to_show;
    }

    for (int i = 0; i < num_to_show; i++) {
        int list_idx = first_entry_idx_in_list + i;
        int display_num = history_start_base + list_idx;

        char* line = os_get_history_entry_line(display_num);
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

        while (*ptr && isspace((unsigned char)*ptr) && !in_single_quotes && !in_double_quotes) {
            ptr++;
        }
        if (!*ptr) break;

        token_pos = 0;
        bool token_started_by_quote = false;
        bool current_segment_had_content = false;

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
                    current_segment_had_content = true;
                    ptr++;
                }
            } else if (in_double_quotes) {
                if (current_char == '"') {
                    in_double_quotes = false;
                    just_exited_quotes = true;
                    ptr++;
                } else if (current_char == '\\' && (*(ptr+1) == '"' || *(ptr+1) == '\\' || *(ptr+1) == '$' || *(ptr+1) == '`')) {
                    ptr++;
                    if (*ptr && token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = *ptr;
                    current_segment_had_content = true;
                    if (*ptr) ptr++;
                } else {
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    current_segment_had_content = true;
                    ptr++;
                }
            } else {
                if (isspace((unsigned char)current_char)) {
                    break;
                } else if (current_char == '\'') {
                    in_single_quotes = true;
                    if (token_pos == 0) token_started_by_quote = true;
                    current_segment_had_content = false;
                    ptr++;
                } else if (current_char == '"') {
                    in_double_quotes = true;
                    if (token_pos == 0) token_started_by_quote = true;
                    current_segment_had_content = false;
                    ptr++;
                } else if (current_char == '\\') {
                    ptr++;
                    if (*ptr) {
                        if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = *ptr;
                        current_segment_had_content = true;
                        ptr++;
                    }
                } else {
                    if (token_pos < MAX_INPUT_LENGTH -1) token_buffer[token_pos++] = current_char;
                    current_segment_had_content = true;
                    ptr++;
                }
            }

            if (just_exited_quotes) {
                if (!*ptr || isspace((unsigned char)*ptr) || *ptr == '\'' || *ptr == '"') {

                    break;
                }

            }

            if (!in_single_quotes && !in_double_quotes && !current_segment_had_content && (!*ptr || isspace((unsigned char)*ptr))) {

                 break;
            }
        }

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

    }

    if (in_single_quotes || in_double_quotes) {

        fprintf(stderr, "bash: syntax error: unterminated quoted string\n");

        for (int i = 0; i < current_arg_idx; i++) free(args[i]);
        free(args);
        *arg_count = 0;
        return NULL;
    }

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

// --- Main Function ---
int main(int argc_main, char *argv_main[]) {
    os_initialize_line_input();
    os_initialize_history_system();

    os_set_completion_handler(shell_completion_func);
    os_set_completion_append_character(' ');

    da_init(&current_completion_matches, 0);

    char *line_buffer_from_os;
    while((line_buffer_from_os = os_read_line("$ ")) != NULL) {
        if (line_buffer_from_os[0] != '\0') {
            os_add_to_history(line_buffer_from_os);
        }

        char *trimmed_line = line_buffer_from_os;
        while (*trimmed_line && isspace((unsigned char)*trimmed_line)) trimmed_line++;

        char *end_of_line = trimmed_line + strlen(trimmed_line);
        while (end_of_line > trimmed_line && isspace((unsigned char)*(end_of_line - 1))) {
            end_of_line--;
        }
        *end_of_line = '\0';

        if (strlen(trimmed_line) == 0) {
            free(line_buffer_from_os);
            continue;
        }

        Pipeline *pipeline = parse_line_into_pipeline(trimmed_line);

        if (pipeline) {
            if (pipeline->num_segments > 0) {
                execute_pipeline(pipeline);
            }
            free_pipeline_resources(pipeline);
        } else {

        }
        free(line_buffer_from_os);
    }

    if (line_buffer_from_os == NULL) {
        if (os_is_tty(OS_STDIN_FD)) {
            printf("\n");
        }
    }

    da_free(&current_completion_matches, true);
    os_cleanup_line_input();

    return 0;
}