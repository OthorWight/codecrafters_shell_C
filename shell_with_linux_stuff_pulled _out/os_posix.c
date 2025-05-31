#define _GNU_SOURCE // For strndup if not implicitly available, and for other POSIX extensions
#include "os_compat.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h> // For FILENAME_MAX, setbuf

#include <readline/readline.h>
#include <readline/history.h>

// --- Standard File Descriptors ---
int OS_STDIN_FD = STDIN_FILENO;
int OS_STDOUT_FD = STDOUT_FILENO;
int OS_STDERR_FD = STDERR_FILENO;

// --- Global for Readline ---
int os_attempted_completion_over = 0; // Mirrored for rl_attempted_completion_over

// --- Process Management ---
os_pid_t os_spawn_process(os_process_start_info_t *start_info) {
    pid_t pid = fork();
    if (pid == -1) {
        return OS_INVALID_PID;
    }
    if (pid == 0) { // Child process
        if (start_info->stdin_fd != OS_STDIN_FD) {
            if (dup2(start_info->stdin_fd, STDIN_FILENO) == -1) _exit(126); // Use _exit for safety
            if (start_info->stdin_fd != pipe(NULL)) { // Avoid closing a pipe fd that might be used by parent
                 // This check is a bit tricky. The idea is not to close an FD that
                 // was explicitly passed for redirection if it's also one end of a pipe
                 // that the parent still needs. Better to let the caller manage closing
                 // pipe ends not needed by the child before calling exec.
                 // For simplicity, let's assume distinct fds or that caller manages.
            }
        }
        if (start_info->stdout_fd != OS_STDOUT_FD) {
            if (dup2(start_info->stdout_fd, STDOUT_FILENO) == -1) _exit(126);
        }
        if (start_info->stderr_fd != OS_STDERR_FD) {
            if (dup2(start_info->stderr_fd, STDERR_FILENO) == -1) _exit(126);
        }

        // As a safety measure, close file descriptors that the child inherited but
        // shouldn't need, especially if they are pipe ends for other stages.
        // This is complex to do generically. For now, we rely on the calling
        // execute_pipeline to close unnecessary pipe ends in the child.

        execv(start_info->argv[0], start_info->argv);
        // If execv returns, it's an error
        perror("execv");
        _exit(errno == ENOENT ? 127 : 126); // 127 for not found, 126 for other exec errors
    }
    // Parent process
    return (os_pid_t)pid;
}

int os_wait_for_process(os_pid_t pid, int *exit_status_ptr) {
    int status;
    if (waitpid((pid_t)pid, &status, 0) == -1) {
        if (exit_status_ptr) *exit_status_ptr = 255; // Indicate error
        return -1; // Error in waiting
    }
    if (exit_status_ptr) {
        if (WIFEXITED(status)) {
            *exit_status_ptr = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            *exit_status_ptr = 128 + WTERMSIG(status);
        } else {
            *exit_status_ptr = 255; // Unknown status
        }
    }
    return 0; // Success
}

// --- Piping ---
bool os_create_pipe(int *read_fd_ptr, int *write_fd_ptr) {
    int fds[2];
    if (pipe(fds) == -1) {
        return false;
    }
    *read_fd_ptr = fds[0];
    *write_fd_ptr = fds[1];
    return true;
}

// --- File Descriptor Operations ---
int os_dup(int old_fd) {
    return dup(old_fd);
}

int os_dup2(int old_fd, int new_fd) {
    return dup2(old_fd, new_fd);
}

void os_close_fd(int fd) {
    close(fd);
}

// --- File System Operations ---
bool os_file_exists_and_is_accessible(const char *path, bool check_execute) {
    int mode = F_OK;
    if (check_execute) {
        mode |= X_OK;
    }
    return access(path, mode) == 0;
}

bool os_is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return false;
}

char *os_find_executable_in_path(const char *command_name) {
    if (command_name == NULL || strlen(command_name) == 0) return NULL;

    // If command_name contains a slash, it's an absolute or relative path
    if (strchr(command_name, '/') != NULL) {
        if (os_file_exists_and_is_accessible(command_name, true)) {
            struct stat st;
            if (stat(command_name, &st) == 0 && !S_ISDIR(st.st_mode)) {
                return strdup(command_name);
            }
        }
        return NULL; // Not found or not executable or is a directory
    }

    char *path_env_original = getenv("PATH");
    if (path_env_original == NULL) return NULL;

    char *path_env_copy = strdup(path_env_original);
    if (path_env_copy == NULL) {
        perror("strdup for PATH in os_find_executable_in_path");
        return NULL;
    }

    char full_executable_path_buffer[PATH_MAX]; // PATH_MAX from limits.h (usually via stdlib or unistd)
    char *found_path_str = NULL;
    char *dir_token = strtok(path_env_copy, ":");

    while (dir_token != NULL) {
        if (strlen(dir_token) > 0) {
            snprintf(full_executable_path_buffer, sizeof(full_executable_path_buffer), "%s/%s", dir_token, command_name);
            if (os_file_exists_and_is_accessible(full_executable_path_buffer, true)) {
                 struct stat st;
                 if (stat(full_executable_path_buffer, &st) == 0 && !S_ISDIR(st.st_mode)) {
                    found_path_str = strdup(full_executable_path_buffer);
                    break; // Found
                }
            }
        }
        dir_token = strtok(NULL, ":");
    }

    free(path_env_copy);
    return found_path_str; // Can be NULL if not found
}


int os_open_file(const char *pathname, int os_flags, int mode) {
    int internal_flags = 0;
    if (os_flags & OS_OPEN_READONLY) internal_flags |= O_RDONLY;
    if (os_flags & OS_OPEN_WRITEONLY) internal_flags |= O_WRONLY;
    if (os_flags & OS_OPEN_READWRITE) internal_flags |= O_RDWR; // POSIX specific
    if (os_flags & OS_OPEN_CREATE) internal_flags |= O_CREAT;
    if (os_flags & OS_OPEN_APPEND) internal_flags |= O_APPEND;
    if (os_flags & OS_OPEN_TRUNCATE) internal_flags |= O_TRUNC;

    return open(pathname, internal_flags, mode);
}

char *os_get_current_dir(char *buffer, size_t size) {
    return getcwd(buffer, size);
}

int os_change_dir(const char *path) {
    return chdir(path);
}


// --- Directory Iteration ---
os_dir_t os_open_dir(const char *name) {
    return (os_dir_t)opendir(name);
}

bool os_read_dir_entry(os_dir_t dir_handle, os_dir_entry_t *entry_ptr) {
    if (!dir_handle || !entry_ptr) return false;
    DIR *d = (DIR*)dir_handle;
    struct dirent *dir_entry_posix;

    errno = 0; // To distinguish end of stream from error
    dir_entry_posix = readdir(d);

    if (dir_entry_posix == NULL) {
        // if (errno != 0) perror("readdir in os_read_dir_entry"); // Optional: log error
        return false; // End of stream or error
    }

    strncpy(entry_ptr->name, dir_entry_posix->d_name, FILENAME_MAX -1);
    entry_ptr->name[FILENAME_MAX -1] = '\0';

    // Check if it's a directory (optional, might need to construct full path for stat)
    // For simplicity, we'll rely on d_type if available, otherwise mark as not a dir
    // A more robust solution would involve stat-ing the entry using its full path.
    #ifdef _DIRENT_HAVE_D_TYPE
        entry_ptr->is_dir = (dir_entry_posix->d_type == DT_DIR);
    #else
        // Fallback: construct path and use stat (more expensive)
        // For now, we'll assume it's not a directory if d_type is not available,
        // or the caller can do a separate os_is_directory call.
        entry_ptr->is_dir = false; // Or call os_is_directory(full_path_to_entry)
                                   // This is a simplification for this example.
                                   // The completion generator in shell_main.c will do a full stat.
    #endif


    return true;
}

void os_close_dir(os_dir_t dir_handle) {
    if (dir_handle) {
        closedir((DIR*)dir_handle);
    }
}

// --- Environment Variables ---
char *os_get_env(const char *name) {
    char *val = getenv(name);
    return val ? strdup(val) : NULL; // POSIX getenv returns pointer to internal static storage
}

int os_set_env(const char *name, const char *value, int overwrite) {
    return setenv(name, value, overwrite);
}

char os_get_path_separator_char(void) {
    return ':';
}

// --- Line Input, History, and Completion (Readline Abstraction) ---
static os_completion_handler_func_t app_completion_handler = NULL;

// This is the function that Readline will call
static char** internal_readline_completion_bridge(const char* text, int start, int end) {
    if (app_completion_handler) {
        // Set the global mirror variable before calling the app's handler
        os_attempted_completion_over = rl_attempted_completion_over;
        char** result = app_completion_handler(text, start, end);
        // Update readline's global from our mirror after the app's handler returns
        rl_attempted_completion_over = os_attempted_completion_over;
        return result;
    }
    return NULL;
}

void os_initialize_line_input(void) {
    // rl_readline_version; // Can be called by app if it cares
    setbuf(stdout, NULL); // Good practice for shells
    setbuf(stderr, NULL);
    rl_attempted_completion_function = internal_readline_completion_bridge;
    // os_attempted_completion_over is handled via the bridge
    // os_set_completion_append_character will set rl_completion_append_character
}

void os_cleanup_line_input(void) {
    // if (rl_clear_history) rl_clear_history(); // This is not needed here, as history is managed separately
    rl_clear_history(); // Clear history if needed
}

char* os_read_line(const char* prompt) {
    return readline(prompt); // readline result needs to be freed by caller
}

void os_add_to_history(const char* line) {
    if (line && line[0] != '\0') { // Only add non-empty lines
        add_history(line);
    }
}

void os_clear_all_history(void) {
    // if (rl_clear_history) rl_clear_history(); // This is the recommended way to clear history in Readline
    rl_clear_history(); // Clear all history entries
}

void os_initialize_history_system(void) {
    using_history();
}

int os_get_history_length(void) {
    return history_length;
}

int os_get_history_base(void) {
    return history_base;
}

char* os_get_history_entry_line(int index_from_offset_base) {
    // readline's history_base is typically 1.
    // The index for history_list() is 0-based from the start of history.
    // If history_base is 1, and user asks for entry 1, it's history_list[0].
    // If user asks for entry `idx` (where `idx` >= history_base),
    // the array index is `idx - history_base`.
    if (index_from_offset_base < history_base || index_from_offset_base >= history_base + history_length) {
        return NULL;
    }
    HIST_ENTRY *he = history_get(index_from_offset_base); // history_get uses 1-based indexing if history_base is 1
    if (he && he->line) {
        return strdup(he->line);
    }
    return NULL;
}


void os_set_completion_handler(os_completion_handler_func_t func) {
    app_completion_handler = func;
    // If func is NULL, readline's rl_attempted_completion_function should also be NULL
    // or a default. The bridge handles func being NULL.
    rl_attempted_completion_function = func ? internal_readline_completion_bridge : NULL;
}

void os_set_completion_append_character(char c) {
    rl_completion_append_character = c;
}

// os_attempted_completion_over is now a global var in this file, manipulated by the bridge
// The application should set `os_attempted_completion_over` inside its handler.

char** os_perform_completion_matches(const char* text_to_complete, os_completion_generator_func_t generator_func) {
    // Readline itself provides rl_completion_matches, which takes the generator.
    // The generator is app-specific.
    return rl_completion_matches(text_to_complete, generator_func);
}

// --- Terminal ---
bool os_is_tty(int fd) {
    return isatty(fd) != 0;
}

// --- Error Handling ---
const char* os_get_last_error_string(void) {
    return strerror(errno);
}

int os_get_last_error_code(void) {
    return errno;
}