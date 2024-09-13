#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdbool.h>
#include<ctype.h>
#define MAX_SIZE 10
#define MAX_LEN 20
typedef struct {
    char data[MAX_SIZE][MAX_LEN];
    int size;
} Queue;

void initQueue(Queue *q) {
    q->size = 0;
}
//we assume that at the beginning password count was below 10, so we never check if number of existing passwords is greater than 10 and truncate the queue accordingly
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

bool pwc(char *p, int n, char *fname, char *lname, char *dob, Queue *q, int wrongs, int prev_count) {
    bool rules[8] = {0};
    int max_digits = 0;
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
        for (int j = 0; j <= n - 5; j++) {
            if (r7(q->data[i], &p[j])) {
                rules[5] = 0;
                break;
            }
        }
        if (rules[5] == 0) break;
    }

    if (r7(p, fname) && r7(p, lname)) {
        rules[6] = 0; 
    } else if (r7(p, fname)) {
        rules[6] = 0;
    } else if (r7(p, lname)) {
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
        if (!rules[5]) printf("Password contains %d characters consecutively similar to one of the past 10 passwords.\n", max_digits);
        if (!rules[6]) {
            if (r7(p, fname) && r7(p, lname)) {
                printf("Password contains name and surname portions of the username.\n");
            } else if (r7(p, fname)) {
                printf("Password contains name portion of the username.\n");
            } else {
                printf("Password contains surname portion of the username.\n");
            }
        }
        if (!rules[7]) printf("Password contains %d digits consecutively similar to the date of birth.\n", max_digits);
        return false;
    }
    
    return true;
}

int main() {
    Queue q;
    initQueue(&q);

    // sample passwords from the sample passwords file plus more random files
    char *initial_passwords[] = {"1aA!wefoboscs","1bB@wfnsofssdfois","4Bb#sofbwfwofwfn","43ghG&fnbqwdfd","2px34sa19h.fS", "lkA@!o90a$5p", "m.M90a21gth*k", "xCXtimPOT23!p", "Abcd.1234.*S","9091@asdfOOP$"};
    for (int i = 0; i < 10; i++) {
        enqueue(&q, initial_passwords[i]);
    }
    
    // Placeholders values until we implement file reading... functionality test of password read
    char fname[] = "ramesh";
    char lname[] = "yadav";
    char dob[] = "19091985"; // have to remove hyphens when reading from file onto temp arr
    int prev_count = 10; // we have kept 10 passwords so far, to be changed if queue is changed
    char new_password[] = "UmeshY@daV1909!"; // should not accept
    for(int i=0;i<3;i++){
        if (pwc(new_password, strlen(new_password), fname, lname, dob, &q, i, prev_count)) {
            enqueue(&q, new_password);//when we get the file, this portion will change
            printf("Password changed successfully.\n");
        } 
        else {
            continue;
        }
    }
    
    return 0;
}
