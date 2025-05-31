#ifndef OS_COMPAT_H
#define OS_COMPAT_H

#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>

// --- Constants for File Operations ---
#define OS_OPEN_READONLY       0x0001
#define OS_OPEN_WRITEONLY      0x0002
#define OS_OPEN_READWRITE      0x0004
#define OS_OPEN_CREATE         0x0008
#define OS_OPEN_APPEND         0x0010
#define OS_OPEN_TRUNCATE       0x0020
#define OS_DEFAULT_FILE_PERMS  0666 

// --- Standard File Descriptors ---

extern int OS_STDIN_FD;
extern int OS_STDOUT_FD;
extern int OS_STDERR_FD;

typedef int os_pid_t;
#define OS_INVALID_PID (-1)

typedef struct {
    char **argv;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
} os_process_start_info_t;

os_pid_t os_spawn_process(os_process_start_info_t *start_info);
int os_wait_for_process(os_pid_t pid, int *exit_status_ptr);

// --- Piping ---
bool os_create_pipe(int *read_fd_ptr, int *write_fd_ptr);

// --- File Descriptor Operations ---
int os_dup(int old_fd);
int os_dup2(int old_fd, int new_fd);
void os_close_fd(int fd);

// --- File System Operations ---
bool os_file_exists_and_is_accessible(const char *path, bool check_execute);
bool os_is_directory(const char *path);
// Returns dynamically allocated string (must be freed by caller) or NULL on failure.
char *os_find_executable_in_path(const char *command_name);
int os_open_file(const char *pathname, int os_flags, int mode);
char *os_get_current_dir(char *buffer, size_t size);
int os_change_dir(const char *path);

// --- Directory Iteration ---
typedef void* os_dir_t;

typedef struct {
    char name[FILENAME_MAX];
    bool is_dir;
} os_dir_entry_t;

os_dir_t os_open_dir(const char *name);

bool os_read_dir_entry(os_dir_t dir_handle, os_dir_entry_t *entry_ptr);
void os_close_dir(os_dir_t dir_handle);

// --- Environment Variables ---

char *os_get_env(const char *name);
int os_set_env(const char *name, const char *value, int overwrite);
char os_get_path_separator_char(void);

// --- Line Input, History, and Completion (Readline Abstraction) ---

typedef char* (*os_completion_generator_func_t)(const char* text, int state);
typedef char** (*os_completion_handler_func_t)(const char* text_line_buffer, int start_index, int end_index);

void os_initialize_line_input(void);
void os_cleanup_line_input(void);
char* os_read_line(const char* prompt);

void os_add_to_history(const char* line);
void os_clear_all_history(void);
void os_initialize_history_system(void);

int os_get_history_length(void);
int os_get_history_base(void);

char* os_get_history_entry_line(int index_from_base);

void os_set_completion_handler(os_completion_handler_func_t func);
void os_set_completion_append_character(char c);

extern int os_attempted_completion_over;

char** os_perform_completion_matches(const char* text_to_complete, os_completion_generator_func_t generator_func);

// --- Terminal ---
bool os_is_tty(int fd);

// --- Error Handling ---

const char* os_get_last_error_string(void);
int os_get_last_error_code(void);

#endif