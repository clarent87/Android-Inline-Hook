#include <stdio.h>

#include "inlineHook.h"

int (*old_puts)(const char *) = NULL; // 타겟의 prologue랑 + jmp 문 으로 원본 돌아가는 트램폴린 아닐까? a맞음 이게 트램폴린 코드

int new_puts(const char *string)
{
    old_puts("inlineHook success");
}

int hook()
{
    if (registerInlineHook((uint32_t) puts, (uint32_t) new_puts, (uint32_t **) &old_puts) != ELE7EN_OK) {
        return -1;
    }
    if (inlineHook((uint32_t) puts) != ELE7EN_OK) {
        return -1;
    }

    return 0;
}

int unHook()
{
    if (inlineUnHook((uint32_t) puts) != ELE7EN_OK) {
        return -1;
    }

    return 0;
}

int main()
{
    puts("test");
    hook();
    puts("test");
    unHook();
    puts("test");
}
