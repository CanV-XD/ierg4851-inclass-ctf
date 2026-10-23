#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MESSAGE_MAX 48

/*
 * Reached only by overwriting the saved return address of feedback().
 * Non-static on purpose: nothing calls it, but the compiler still has to emit
 * it, so `nm` finds it and it keeps a fixed address (no PIE).
 */
void win(void)
{
    puts("[*] feedback accepted");
    execve("/bin/sh", NULL, NULL);
}

void feedback(void)
{
    unsigned int size;
    char message[MESSAGE_MAX];

    puts("how long is your feedback?");
    if (scanf("%u", &size) != 1) {
        puts("that was not a number");
        exit(1);
    }
    printf("noted: %u\n", size);

    puts("go ahead:");
    read(STDIN_FILENO, message, size);

    printf("thanks, %u bytes stored\n", size);
}

void prepare(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(120);
}

int main(void)
{
    prepare();
    puts("== feedback box ==");
    feedback();
    return 0;
}
