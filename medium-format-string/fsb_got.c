#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LINE_MAX 0x100

void prepare(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(120);
}

int main(void)
{
    char line[LINE_MAX];

    prepare();
    puts("== echo server ==");

    for (int i = 0; i < 3; i++) {
        write(STDOUT_FILENO, "say something: ", 15);
        read(STDIN_FILENO, line, LINE_MAX);
        printf(line);
        write(STDOUT_FILENO, "\n", 1);
    }

    return 0;
}
