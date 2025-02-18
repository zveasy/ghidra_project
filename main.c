/* main.c */
#include <stdio.h>

// Declare main() before using it in _start()
int main();

void _start() {
    // Call main function
    int result = main();

    // Infinite loop to prevent return
    while (1);
}

int test_func() {
    return 42;
}

int main() {
    printf("Hello world!\n");
    int result = test_func();
    return 0;
}
