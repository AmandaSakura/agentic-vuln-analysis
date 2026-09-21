#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

static void append_text(int fd, const char *text) {
    size_t length = strlen(text);
    while (length > 0) {
        ssize_t written = write(fd, text, length);
        if (written <= 0) {
            return;
        }
        text += written;
        length -= (size_t)written;
    }
}

static void append_json_string(int fd, const char *value) {
    append_text(fd, "\"");
    if (value != NULL) {
        for (const unsigned char *cursor = (const unsigned char *)value; *cursor; cursor++) {
            char buffer[8];
            if (*cursor == '"' || *cursor == '\\') {
                buffer[0] = '\\';
                buffer[1] = (char)*cursor;
                buffer[2] = '\0';
                append_text(fd, buffer);
            } else if (*cursor >= 0x20 && *cursor <= 0x7e) {
                buffer[0] = (char)*cursor;
                buffer[1] = '\0';
                append_text(fd, buffer);
            } else {
                snprintf(buffer, sizeof(buffer), "\\u%04x", *cursor);
                append_text(fd, buffer);
            }
        }
    }
    append_text(fd, "\"");
}

static void append_json_array(int fd, char *const values[]) {
    append_text(fd, "[");
    if (values != NULL) {
        for (int index = 0; values[index] != NULL; index++) {
            if (index > 0) {
                append_text(fd, ",");
            }
            append_json_string(fd, values[index]);
        }
    }
    append_text(fd, "]");
}

static void record_exec_at(const char *log_path, const char *kind, const char *path,
                           char *const argv[], char *const envp[]) {
    if (log_path == NULL || log_path[0] == '\0') {
        return;
    }
    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    append_text(fd, "{\"kind\":");
    append_json_string(fd, kind);
    append_text(fd, ",\"path\":");
    append_json_string(fd, path);
    append_text(fd, ",\"argv\":");
    append_json_array(fd, argv);
    append_text(fd, ",\"envp\":");
    append_json_array(fd, envp);
    append_text(fd, "}\n");
    close(fd);
}

static void record_exec(const char *kind, const char *path, char *const argv[], char *const envp[]) {
    record_exec_at(getenv("CV_AGENT_EXEC_LOG"), kind, path, argv, envp);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    record_exec("execve", pathname, argv, envp);
    errno = EACCES;
    return -1;
}

int execv(const char *path, char *const argv[]) {
    record_exec("execv", path, argv, environ);
    errno = EACCES;
    return -1;
}

int execvp(const char *file, char *const argv[]) {
    record_exec("execvp", file, argv, environ);
    errno = EACCES;
    return -1;
}

int execvpe(const char *file, char *const argv[], char *const envp[]) {
    record_exec("execvpe", file, argv, envp);
    errno = EACCES;
    return -1;
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) {
    (void)dirfd;
    (void)flags;
    record_exec("execveat", pathname, argv, envp);
    errno = EACCES;
    return -1;
}

int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    (void)pid;
    (void)file_actions;
    (void)attrp;
    record_exec("posix_spawn", path, argv, envp);
    return EACCES;
}

int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    (void)pid;
    (void)file_actions;
    (void)attrp;
    record_exec("posix_spawnp", file, argv, envp);
    return EACCES;
}
