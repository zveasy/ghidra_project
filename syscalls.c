#include <sys/types.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <stddef.h>

// Stub implementation for system calls

int _close(int file) {
    return -1;
}

off_t _lseek(int file, off_t ptr, int dir) {  
    return (off_t)0;
}

int _read(int file, void *ptr, size_t len) {  // Corrected return type to int
    return 0;
}

int _write(int file, const void *ptr, size_t len) {  // Corrected return type to int
    return len;
}

void *_sbrk(ptrdiff_t incr) {  
    return (void *)-1;
}

int _fstat(int file, struct stat *st) {
    st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int file) {
    return 1;
}

// Provide correct weak aliases for syscall functions
__attribute__((weak)) int close(int file) { return _close(file); }
__attribute__((weak)) off_t lseek(int file, off_t ptr, int dir) { return _lseek(file, ptr, dir); }
__attribute__((weak)) int read(int file, void *ptr, size_t len) { return _read(file, ptr, len); }  // Changed return type
__attribute__((weak)) int write(int file, const void *ptr, size_t len) { return _write(file, ptr, len); }  // Changed return type
__attribute__((weak)) void *sbrk(ptrdiff_t incr) { return _sbrk(incr); }
__attribute__((weak)) int fstat(int file, struct stat *st) { return _fstat(file, st); }
__attribute__((weak)) int isatty(int file) { return _isatty(file); }
