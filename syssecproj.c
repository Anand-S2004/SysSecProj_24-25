#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>

#define MAX_SIZE 10
#define MAX_LEN 20

typedef struct {
    char data[MAX_SIZE][MAX_LEN];
    int size;
} Queue;

void initQueue(Queue *q) {
    q->size = 0;
}


void enqueue(Queue *q, const char *password) {
    if (q->size < MAX_SIZE) {
        for (int i = q->size-1; i >= 0; i--) {
            strcpy(q->data[i+1], q->data[i]);
        }
        strcpy(q->data[0], password);
        q->size++;
    } else {
        for (int i = MAX_SIZE - 2; i >= 0; i--) {
            strcpy(q->data[i+1], q->data[i]);
        }
        strcpy(q->data[0], password);
    }
}

void initial_enqueue(Queue *q, const char *password){
	strcpy(q->data[q->size], password);
	q->size++;
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

int charmatch(const char *password, const char *str) {
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
    return max_match;
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
        }
    }
    for (int i = 0; i < q->size; i++) {
        max_chars = charmatch(p, q->data[i]);
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
        printf("Attempt %d failed.\n", wrongs+1);
        if (!rules[0]) printf("Password does not contain a minimum of 12 characters.\n");
        if (!rules[1]) printf("Password does not contain at least one lowercase letter.\n");
        if (!rules[2]) printf("Password does not contain at least one uppercase letter.\n");
        if (!rules[3]) printf("Password does not contain at least one digit.\n");
        if (!rules[4]) printf("Password does not contain at least one of the allowed special characters.\n");
        if (!rules[5]) printf("Password contains %d characters consecutively similar to one of the past 10 passwords.\n", max_chars);

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

void readMaster(char *fname, char *lname, char *dob, char *password_file) {
    FILE *file = fopen("masterfile.txt", "r");
    if (file == NULL) {
        printf("Error opening file.\n");
        exit(1);
    }

    char username[50], dob_read[15], pwdfile[50];
    bool found = false;

    while (fscanf(file, "%s %s %s", username, dob_read, pwdfile) != EOF) {
        char full_name[40];
        sprintf(full_name, "%s.%s", fname, lname); 
        if (strcmp(username, full_name) == 0) {
            strcpy(dob, dob_read);
            strcpy(password_file, pwdfile);
            found = true;
            break;
        }
    }
    fclose(file);

    if (!found) {
        printf("User not found in the master file.\n");
        exit(1);
    }

    for (int i = 0, j = 0; dob_read[i] != '\0'; i++) {
        if (dob_read[i] != '-') {
            dob[j++] = dob_read[i];
        }
    }
}

void loadPwd(Queue *q, char *password_file) {
    FILE *file = fopen(password_file, "r");
    if (file == NULL) {
        printf("Error opening password file.\n");
        exit(1);
    }

    char pwd[MAX_LEN];
    while (fscanf(file, "%s", pwd) != EOF) {
        initial_enqueue(q, pwd);
    }
    fclose(file);
}

void savePwd(Queue *q, char *password_file) {
    FILE *file = fopen(password_file, "w");
    if (file == NULL) {
        printf("Error opening password file to write.\n");
        exit(1);
    }

    for (int i = 0; i < q->size; i++) {
        fprintf(file, "%s\n", q->data[i]);
    }
    fclose(file);
}

bool checkLog(Queue *q, const char *password_file, const char *entered_password) {
    FILE *file = fopen(password_file, "r");
    if (file == NULL) {
        printf("Error opening password file.\n");
        return false;
    }

    char most_recent_password[MAX_LEN];
    if (fscanf(file, "%s", most_recent_password) != EOF) {
        fclose(file);
        return strcmp(most_recent_password, entered_password) == 0;
    }

    fclose(file);
    return false;
}

int main() {
    Queue q;
    initQueue(&q);

    char fname[50], lname[50], dob[15], password_file[50];
    char full_name[50];

    printf("Enter username (first.last): ");
    scanf("%s", full_name);
    //separate into first name,last name, imortant for name matching
    char *token = strtok(full_name, ".");
    strcpy(fname, token);
    token = strtok(NULL, ".");
    strcpy(lname, token);

    readMaster(fname, lname, dob, password_file);

    loadPwd(&q, password_file);

    int wrongs = 0;
    char new_password[MAX_LEN];

    while (true) {
        printf("Enter current password for login: ");
        char entered_password[MAX_LEN];
        scanf("%s", entered_password);

        if (checkLog(&q, password_file, entered_password)) {
            printf("Login successful.\n");
            break;
        } else {
            printf("Login failed. Please try again.\n");
            wrongs++;
            if (wrongs == 3) {
                printf("Wrong password entered 3 times. Exiting application...\n");
                return 1;
            }
        }
    }
    int sleeping[3]={1,2,3};//use 8,16,32 during actual implementation
    wrongs = 0;
    while (true) {
        printf("Enter new password (%dth attempt): ",wrongs+1);
        scanf("%s", new_password);

        if (pwc(new_password, strlen(new_password), fname, lname, dob, &q, wrongs)) {
            enqueue(&q, new_password);
            savePwd(&q, password_file);
            printf("Password changed successfully.\n");
            break;
        } else {
            wrongs++;
            if (wrongs == 4) {
                printf("All 4 attempts failed. You need to try again later. \n");
                return 1;
            }
            int i=wrongs-1;
            while(sleeping[i]!=0){
                printf("Please wait for %d seconds \n",sleeping[i]);
                sleeping[i]--;
                fflush(stdout);//this is to print stdout immediately
                sleep(1);
            }
        }
    }

    return 0;
}
