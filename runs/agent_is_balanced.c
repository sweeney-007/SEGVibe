#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STACK_SIZE 1000000 // Maximum size of the stack

int is_balanced(const char *s) {
    if (s == NULL) {
        return -1;
    }

    int stack[MAX_STACK_SIZE];
    int top = -1;

    for (const char *p = s; *p != '\0'; p++) {
        switch (*p) {
            case '(':
            case '[':
            case '{':
                stack[++top] = *p;
                break;
            case ')':
                if (top == -1 || stack[top] != '(') {
                    return 0;
                }
                top--;
                break;
            case ']':
                if (top == -1 || stack[top] != '[') {
                    return 0;
                }
                top--;
                break;
            case '}':
                if (top == -1 || stack[top] != '{') {
                    return 0;
                }
                top--;
                break;
        }
    }

    return top == -1 ? 1 : 0;
}

// Example usage
int main() {
    const char *test1 = "()[]{}";
    const char *test2 = "(]";
    const char *test3 = "{[()]}";
    const char *test4 = "([)]";

    printf("%d\n", is_balanced(test1)); // Expected output: 1
    printf("%d\n", is_balanced(test2)); // Expected output: 0
    printf("%d\n", is_balanced(test3)); // Expected output: 1
    printf("%d\n", is_balanced(test4)); // Expected output: 0

    return 0;
}
