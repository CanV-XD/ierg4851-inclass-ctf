#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PROFILES 16

/*
 * sizeof(struct profile) is 0x60 — the three fields and the pointer add up to
 * exactly 0x60 with no padding, which is what the build's self-check asserts.
 * The sizes here are load-bearing: see ictf-ta/README.md before changing any of
 * them.
 */
struct profile {
    char name[0x20];
    char password[0x20];
    char *bio;
    char tagline[0x18];
};

static struct profile *profiles[MAX_PROFILES];

/* Non-static on purpose: nothing calls it, so `nm` finds it. No PIE. */
void backdoor(void)
{
    system("/bin/sh");
}

void prepare(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(120);
}

static int pick_profile(void)
{
    int index;

    printf("index > ");
    if (scanf("%d", &index) != 1)
        exit(1);

    if (index < 0 || index >= MAX_PROFILES) {
        puts("no such profile");
        return -1;
    }
    if (!profiles[index]) {
        puts("no such profile");
        return -1;
    }
    return index;
}

static int password_ok(struct profile *p)
{
    char entered[0x20] = {0};

    printf("password > ");
    read(STDIN_FILENO, entered, 0x20);

    if (strcmp(entered, p->password) != 0) {
        puts("wrong password");
        return -1;
    }
    return 0;
}

static void create_profile(void)
{
    int slot = -1;
    struct profile *p;
    char *bio;

    for (int i = 0; i < MAX_PROFILES; i++) {
        if (!profiles[i]) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        puts("the address book is full");
        return;
    }

    p = malloc(sizeof(struct profile));
    if (!p) {
        puts("out of memory");
        return;
    }

    printf("name > ");
    read(STDIN_FILENO, p->name, 0x20);
    printf("password > ");
    read(STDIN_FILENO, p->password, 0x20);

    bio = malloc(0x40);
    if (!bio) {
        free(p);
        puts("out of memory");
        return;
    }
    printf("bio > ");
    read(STDIN_FILENO, bio, 0x40);
    p->bio = bio;

    printf("tagline > ");
    read(STDIN_FILENO, p->tagline, 0x18);

    profiles[slot] = p;
    printf("profile %s saved at index %d\n", p->name, slot);
}

static void delete_profile(void)
{
    int index = pick_profile();
    struct profile *p;

    if (index < 0)
        return;
    p = profiles[index];

    if (password_ok(p) != 0)
        return;

    printf("profile %s removed from index %d\n", p->name, index);
    free(p->bio);
    free(p);
    profiles[index] = NULL;
}

static void show_profile(void)
{
    int index = pick_profile();
    struct profile *p;

    if (index < 0)
        return;
    p = profiles[index];

    if (password_ok(p) != 0)
        return;

    printf("name: ");
    write(STDOUT_FILENO, p->name, 0x20);
    printf("\ntagline: ");
    write(STDOUT_FILENO, p->tagline, 0x18);
    printf("\nbio: ");
    write(STDOUT_FILENO, p->bio, 0x40);
    printf("\n");
}

static void edit_profile(void)
{
    int index = pick_profile();
    struct profile *p;

    if (index < 0)
        return;
    p = profiles[index];

    if (password_ok(p) != 0)
        return;

    printf("new name > ");
    read(STDIN_FILENO, p->name, 0x20);
    printf("new bio > ");
    read(STDIN_FILENO, p->bio, 0x60);
    printf("new tagline > ");
    read(STDIN_FILENO, p->tagline, 0x18);
    profiles[index] = p;
}

static void menu(void)
{
    puts("[1] create profile");
    puts("[2] delete profile");
    puts("[3] show profile");
    puts("[4] edit profile");
    puts("[5] leave");
    printf("> ");
}

int main(void)
{
    int choice;

    prepare();

    while (1) {
        menu();
        if (scanf("%d", &choice) != 1)
            exit(1);

        switch (choice) {
        case 1: create_profile(); break;
        case 2: delete_profile(); break;
        case 3: show_profile();   break;
        case 4: edit_profile();   break;
        case 5: return 0;
        default: puts("unknown option"); break;
        }
    }
}
