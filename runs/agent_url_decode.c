#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 1024 // Maximum length of the input string

char *url_decode(const char *s) {
    if (s == NULL) {
        return NULL;
    }

    size_t len = strlen(s);
    char *decoded = (char *)malloc(len + 1); // Allocate memory for the decoded string
    if (decoded == NULL) {
        return NULL;
    }

    size_t i = 0;
    size_t j = 0;

    while (i < len) {
        if (s[i] == '+') {
            decoded[j++] = ' ';
        } else if (s[i] == '%') {
            if (i + 2 >= len || !isxdigit(s[i + 1]) || !isxdigit(s[i + 2])) {
                free(decoded);
                return NULL;
            }
            int high = s[i + 1] - '0';
            int low = s[i + 2] - '0';
            decoded[j++] = (high << 4) | low;
            i += 2;
        } else {
            decoded[j++] = s[i++];
        }
    }

    decoded[j] = '\0'; // Null terminate the string
    return decoded;
}

// Example usage
int main() {
    const char *input = "Hello%20World";
    char *output = url_decode(input);
    if (output != NULL) {
        printf("Decoded: %s\n", output);
        free(output);
    } else {
        printf("Failed to decode\n");
    }
    return 0;
}
