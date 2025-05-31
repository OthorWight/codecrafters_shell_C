// os_compat.h

#ifndef OS_COMPAT_H
#define OS_COMPAT_H

#include <stdbool.h>  // For bool type
#include <stdio.h>    // For FILE*, FILENAME_MAX (used in os_dir_entry_t)
#include <stddef.h>   // For size_t

// --- Constants for File Operations ---
#define OS_OPEN_READONLY       0x0001
#define OS_OPEN_WRITEONLY      0x0002
#define OS_OPEN_READWRITE      0x0004 // If you need it
#define OS_OPEN_CREATE         0x0008
#define OS_OPEN_APPEND         0x0010
#define OS_OPEN_TRUNCATE       0x0020
#define OS_DEFAULT_FILE_PERMS  0666   // POSIX style, Windows impl would ignore or map

// --- Standard File Descriptors ---
// These will be defined in the .c file (e.g., os_posix.c)
extern int OS_STDIN_FD;
extern int OS_STDOUT_FD;
extern int OS_STDERR_FD;

// --- Process Management ---
typedef int os_pid_t; // On POSIX, pid_t is int. On Windows, could be HANDLE (void*)
#define OS_INVALID_PID (-1)

typedef struct {
    char **argv;             // Argument vector, argv[0] should be path to executable
    int stdin_fd;            // File descriptor for stdin redirection
    int stdout_fd;           // File descriptor for stdout redirection
    int stderr_fd;           // File descriptor for stderr redirection
} os_process_start_info_t;

os_pid_t os_spawn_process(os_process_start_info_t *start_info);
int os_wait_for_process(os_pid_t pid, int *exit_status_ptr); // Returns 0 on success, -1 on error

// --- Piping ---
bool os_create_pipe(int *read_fd_ptr, int *write_fd_ptr);

// --- File Descriptor Operations ---
int os_dup(int old_fd);
int os_dup2(int old_fd, int new_fd);
void os_close_fd(int fd);

// --- File System Operations ---
bool os_file_exists_and_is_accessible(const char *path, bool check_execute); // Replaces access(path, F_OK/X_OK)
bool os_is_directory(const char *path);
// Returns dynamically allocated string (must be freed by caller) or NULL on failure.
char *os_find_executable_in_path(const char *command_name);
int os_open_file(const char *pathname, int os_flags, int mode); // mode is for creation
char *os_get_current_dir(char *buffer, size_t size);
int os_change_dir(const char *path);

// --- Directory Iteration ---
typedef void* os_dir_t; // Abstract type for directory stream (DIR* on POSIX)

typedef struct {
    char name[FILENAME_MAX]; // FILENAME_MAX from stdio.h should be portable enough
    bool is_dir;
} os_dir_entry_t;

os_dir_t os_open_dir(const char *name);
// Returns true if an entry was read, false if no more entries or error
bool os_read_dir_entry(os_dir_t dir_handle, os_dir_entry_t *entry_ptr);
void os_close_dir(os_dir_t dir_handle);

// --- Environment Variables ---
// Returns dynamically allocated string (must be freed) or NULL if not found/error
char *os_get_env(const char *name);
int os_set_env(const char *name, const char *value, int overwrite);
char os_get_path_separator_char(void); // ':' on POSIX, ';' on Windows

// --- Line Input, History, and Completion (Readline Abstraction) ---
// Callback types for completion
typedef char* (*os_completion_generator_func_t)(const char* text, int state);
typedef char** (*os_completion_handler_func_t)(const char* text_line_buffer, int start_index, int end_index);

void os_initialize_line_input(void);
void os_cleanup_line_input(void);
char* os_read_line(const char* prompt); // Caller must free the returned string

void os_add_to_history(const char* line);
void os_clear_all_history(void); // Corresponds to rl_clear_history
void os_initialize_history_system(void); // Corresponds to using_history()

int os_get_history_length(void);
int os_get_history_base(void); // Starting number for history (e.g., 1)
// Returns dynamically allocated string (caller frees) for the line, or NULL
char* os_get_history_entry_line(int index_from_base);


// Completion specific functions
void os_set_completion_handler(os_completion_handler_func_t func);
void os_set_completion_append_character(char c);
// This variable is used by the completion handler to signal if it handled completion.
// It's defined in os_posix.c (or other OS-specific .c file).
extern int os_attempted_completion_over;
// Called by the user's completion handler to get matches from a generator.
char** os_perform_completion_matches(const char* text_to_complete, os_completion_generator_func_t generator_func);


// --- Terminal ---
bool os_is_tty(int fd); // Checks if a file descriptor is a terminal

// --- Error Handling ---
// Returns a string describing the last error (like strerror(errno))
// The returned string might be static, do not free.
const char* os_get_last_error_string(void);
int os_get_last_error_code(void); // e.g., errno

#endif // OS_COMPAT_H  <--- This is the crucial closing #endif for the include guard