/* Small Windows test program used for GhidraWorker's end-to-end test. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int id;
    char name[32];
    double score;
} Player;

static int checksum(const char *s) {
    int sum = 0;
    while (*s) sum = sum * 31 + *s++;
    return sum;
}

static void print_player(const Player *p) {
    printf("Player %d: %s (%.2f) chk=%d\n", p->id, p->name, p->score, checksum(p->name));
}

int main(int argc, char **argv) {
    Player p = { 42, "GhidraWorker", 13.37 };
    if (argc > 1) strncpy(p.name, argv[1], sizeof(p.name) - 1);
    print_player(&p);
    MessageBoxA(NULL, "Hello from the rebuild test", "GhidraWorker", MB_OK);
    return (int)GetTickCount() & 1;
}
