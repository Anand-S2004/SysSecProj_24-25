#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_USERS 100
#define MAX_PERMISSIONS 100

// Structure to hold biclique data
typedef struct {
    bool users[MAX_USERS];
    bool permissions[MAX_PERMISSIONS];
} Biclique;

// Function to initialize UPA matrix
int** upaspc(int rows, int cols) {
    int** matrix = (int**)malloc(rows * sizeof(int*));
    for (int i = 0; i < rows; i++) {
        matrix[i] = (int*)calloc(cols, sizeof(int)); 
    }
    return matrix;
}

// Function to read UPA matrix from file
int** readmat(const char* filename, int *users, int *perms) {
    FILE* file = fopen(filename, "r");
    fscanf(file, "%d", users);
    fscanf(file, "%d", perms);
    int** upamat = upaspc(*users, *perms);
    int row, col;
    while (fscanf(file, "%d %d", &row, &col) == 2) {
        upamat[row - 1][col - 1] = 1;
    }

    fclose(file);
    return upamat;
}

// Algorithm 5 to form biclique starting with a user vertex
void algorithm5_user(int v, int** upamat, int users, int perms, int* UserRoleCount, int rconstr, int* PermRoleCount, int pconstr, Biclique* biclique) {
    biclique->users[v] = true;
    UserRoleCount[v] += 1;

    // Add permissions of user v to P
    for (int p = 0; p < perms; p++) {
        if (upamat[v][p] == 1 && PermRoleCount[p] < pconstr - 1) {
            biclique->permissions[p] = true;
            PermRoleCount[p] += 1;
        }
    }

    // Add other users with similar permissions to U
    for (int u = 0; u < users; u++) {
        if (u != v && UserRoleCount[u] < rconstr - 1) {
            bool allPermsMatch = true;
            for (int p = 0; p < perms; p++) {
                if (biclique->permissions[p] && upamat[u][p] == 0) {
                    allPermsMatch = false;
                    break;
                }
            }
            if (allPermsMatch) {
                biclique->users[u] = true;
                UserRoleCount[u] += 1;
            }
        }
    }
}

// Dual of Algorithm 5, starting with a permission vertex
void algorithm5_permission(int v, int** upamat, int users, int perms, int* UserRoleCount, int rconstr, int* PermRoleCount, int pconstr, Biclique* biclique) {
    biclique->permissions[v] = true;
    PermRoleCount[v] += 1;

    // Add users with permission v to U
    for (int u = 0; u < users; u++) {
        if (upamat[u][v] == 1 && UserRoleCount[u] < rconstr - 1) {
            biclique->users[u] = true;
            UserRoleCount[u] += 1;
        }
    }

    // Add permissions common to all users in U to P
    for (int p = 0; p < perms; p++) {
        bool allUsersMatch = true;
        for (int u = 0; u < users; u++) {
            if (biclique->users[u] && upamat[u][p] == 0) {
                allUsersMatch = false;
                break;
            }
        }
        if (allUsersMatch && PermRoleCount[p] < pconstr - 1) {
            biclique->permissions[p] = true;
            PermRoleCount[p] += 1;
        }
    }
}

// Phase 1 and Phase 2 for biclique formation
void enforceConstraints(int** upamat, int users, int perms, int rconstr, int pconstr) {
    int UserRoleCount[MAX_USERS] = {0};
    int PermRoleCount[MAX_PERMISSIONS] = {0};
    Biclique* bicliqueCover[MAX_USERS * MAX_PERMISSIONS];
    int bicliqueCount = 0;

    // PHASE 1
    for (int u = 0; u < users; u++) {
        for (int p = 0; p < perms; p++) {
            if (upamat[u][p] == 1 && (UserRoleCount[u] < rconstr - 1 || PermRoleCount[p] < pconstr - 1)) {
                Biclique* newBiclique = (Biclique*)malloc(sizeof(Biclique));
                for (int i = 0; i < users; i++) newBiclique->users[i] = false;
                for (int j = 0; j < perms; j++) newBiclique->permissions[j] = false;

                if (UserRoleCount[u] < rconstr - 1) {
                    algorithm5_user(u, upamat, users, perms, UserRoleCount, rconstr, PermRoleCount, pconstr, newBiclique);
                } else {
                    algorithm5_permission(p, upamat, users, perms, UserRoleCount, rconstr, PermRoleCount, pconstr, newBiclique);
                }

                bicliqueCover[bicliqueCount++] = newBiclique;
            }
        }
    }

    // PHASE 2 (with stricter constraints)
    for (int u = 0; u < users; u++) {
        if (UserRoleCount[u] == rconstr - 1) {
            Biclique* newBiclique = (Biclique*)malloc(sizeof(Biclique));
            for (int i = 0; i < users; i++) newBiclique->users[i] = false;
            for (int j = 0; j < perms; j++) newBiclique->permissions[j] = false;

            algorithm5_user(u, upamat, users, perms, UserRoleCount, rconstr, PermRoleCount, pconstr, newBiclique);
            bicliqueCover[bicliqueCount++] = newBiclique;
        }
    }

    // Output results
    printf("Biclique Cover (Total Roles Formed: %d):\n", bicliqueCount);
    for (int i = 0; i < bicliqueCount; i++) {
        printf("Biclique %d:\n  Users: ", i + 1);
        for (int u = 0; u < users; u++) {
            if (bicliqueCover[i]->users[u]) printf("U%d ", u + 1);
        }
        printf("\n  Permissions: ");
        for (int p = 0; p < perms; p++) {
            if (bicliqueCover[i]->permissions[p]) printf("P%d ", p + 1);
        }
        printf("\n");
    }

    // Free allocated memory
    for (int i = 0; i < bicliqueCount; i++) {
        free(bicliqueCover[i]);
    }
}

int main() {
    char filename[20];
    int users, perms;
    int rconstr, pconstr;

    printf("Enter the name of the UPA matrix file: ");
    scanf("%s", filename);
    int** upamat = readmat(filename, &users, &perms);

    printf("Enter the value of the role-usage cardinality constraint: ");
    scanf("%d", &rconstr);
    printf("Enter the value of the permission-distribution cardinality constraint: ");
    scanf("%d", &pconstr);

    enforceConstraints(upamat, users, perms, rconstr, pconstr);

    // Free UPA matrix memory
    for (int i = 0; i < users; i++) {
        free(upamat[i]);
    }
    free(upamat);

    return 0;
}
