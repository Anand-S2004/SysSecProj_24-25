#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdbool.h>
#include<ctype.h>
#include<unistd.h>
#define MAX_SIZE 10
#define MAX_LEN 20

typedef struct {
    char data[MAX_SIZE][MAX_LEN];
    int size;
} Queue;

void initQueue(Queue *q) {
    q->size = 0;
}

//we assume that at the beginning password count was below 10, so we never check f number of existing passwords is greater than 10 and truncate the queue accordingly
void enqueue(Queue *q, const char *password) {
    if (q->size == MAX_SIZE) {
        for (int i = 1; i < MAX_SIZE; i++) {
            strcpy(q->data[i - 1], q->data[i]);
        }
        strcpy(q->data[MAX_SIZE - 1], password);
    } else {
        strcpy(q->data[q->size], password);
        q->size++;
    }
}

bool r7(const char *str, const char *sub) {
    int len_str = strlen(str);
    int len_sub = strlen(sub);
    
    for (int i = 0; i <= len_str - len_sub; i++) {
        bool match = true;
        for (int j = 0; j < len_sub; j++) {
            if (tolower(str[i + j]) != tolower(sub[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

bool r8(const char *password, const char *dob, int *max_digits) {
    int len_pwd = strlen(password);
    int len_dob = strlen(dob);
    *max_digits = 0;

    for (int i = 0; i <= len_pwd - 3; i++) {
        for (int j = 0; j <= len_dob - 3; j++) {
            int match = 0;
            while (j + match < len_dob && i + match < len_pwd && dob[j + match] == password[i + match] && isdigit(dob[j + match])) {
                match++;
            }
            if (match > *max_digits) {
                *max_digits = match;
            }
        }
    }
    return *max_digits > 3; 
}

int match_consecutive_chars(const char *password, const char *str) {
    int len_pwd = strlen(password);
    int len_str = strlen(str);
    int max_match = 0;

    for (int i = 0; i <= len_pwd - 5; i++) {
        for (int j = 0; j <= len_str - 5; j++) {
            int match = 0;
            while (j + match < len_str && i + match < len_pwd && tolower(password[i + match]) == tolower(str[j + match])) {
                match++;
            }
            if (match > max_match) {
                max_match = match;
            }
        }
    }
    return max_match; // returns the maximum number of consecutive matching characters
}
bool pwc(char *p, int n, char *fname, char *lname, char *dob, Queue *q, int wrongs) {
    bool rules[8] = {0};
    int max_digits = 0, max_chars = 0;
    bool name_matches = false, surname_matches = false;

    rules[5] = rules[6] = rules[7] = 1;
    if (n >= 12) rules[0] = 1;
    
    for (int i = 0; i < n; i++) {
        if (islower(p[i])) rules[1] = 1;
        if (isupper(p[i])) rules[2] = 1;
        if (isdigit(p[i])) rules[3] = 1;
        if (p[i] == '.' || p[i] == '@' || p[i] == '!' || p[i] == '#' || p[i] == '$' || p[i] == '%' || p[i] == '^' || p[i] == '&' || p[i] == '*' || p[i] == '-' || p[i] == '_') {
            rules[4] = 1;
        }//due to lack of ascii range, I have just included the symbols themselves, if you guys find a better way to increase readability then you can modify it
    }
    for (int i = 0; i < q->size; i++) {
        max_chars = match_consecutive_chars(p, q->data[i]);
        if (max_chars > 4) {
            rules[5] = 0;
            break;
        }
    }
    name_matches = r7(p, fname);
    surname_matches = r7(p, lname);
    
    if (name_matches || surname_matches) {
        rules[6] = 0;
    }
    rules[7] = !r8(p, dob, &max_digits);
    if (!rules[0] || !rules[1] || !rules[2] || !rules[3] || !rules[4] || !rules[5] || !rules[6] || !rules[7]) {
        printf("Attempt %d failed.\n", wrongs);
        if (!rules[0]) printf("Password does not contain a minimum of 12 characters.\n");
        if (!rules[1]) printf("Password does not contain at least one lowercase letter.\n");
        if (!rules[2]) printf("Password does not contain at least one uppercase letter.\n");
        if (!rules[3]) printf("Password does not contain at least one digit.\n");
        if (!rules[4]) printf("Password does not contain at least one of the allowed special characters.\n");
        if (!rules[5]) printf("Password contains %d characters consecutively similar to one of the past 10 passwords.\n", max_chars);

        // Output specific message based on whether name or surname or both matched
        if (name_matches && surname_matches) {
            printf("Password contains name and surname portions of the username.\n");
        } else if (name_matches) {
            printf("Password contains name portion of the username.\n");
        } else if (surname_matches) {
            printf("Password contains surname portion of the username.\n");
        }

        if (!rules[7]) printf("Password contains %d digits consecutively similar to the date of birth.\n", max_digits);
        return false;
    }

    return true;
}

int main() {
    Queue q;
    initQueue(&q);
    char *initial_passwords[] = {"1aA!wefoboscs","1bB@wfnsofssdfois","4Bb#sofbwfwofwfn","43ghG&fnbqwdfd","2px34sa19h.fS", "lkA@!o90a$5p", "m.M90a21gth*k", "xCXtimPOT23!p", "Abcd.1234.*S","9091@asdfOOP$"};
    for (int i = 0; i < 10; i++) {
        enqueue(&q, initial_passwords[i]);
    }

    int sleeping[3] = {0, 0, 0}; // change to 8, 16, and 32 later

    // Placeholder values for fname, lname, dob
    char fname[] = "ramesh";
    char lname[] = "yadav";
    char dob[] = "19091985"; // should remove hyphens when reading from a file
    char new_password[] = "rameshyadav1985"; // should not accept due to multiple rules

    for (int i = 0; i < 4; i++) {
        if (pwc(new_password, strlen(new_password), fname, lname, dob, &q, i + 1)) {
            enqueue(&q, new_password); // Add to queue if password is accepted
            printf("Password changed successfully.\n");
            return 0;
        } else {
            if (i == 3) {
                printf("Too many bad login attempts. Exiting.\n");
                return 0;
            }
            sleep(sleeping[i]);
        }
    }

    return 0;
}
