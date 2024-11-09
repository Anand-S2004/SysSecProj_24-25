#include <stdio.h>
#include <stdlib.h>
int** upaspc(int rows, int cols) {
    int** matrix = (int**)malloc(rows * sizeof(int*));
    for (int i = 0; i < rows; i++) {
        matrix[i] = (int*)calloc(cols, sizeof(int)); 
    }
    return matrix;
}

int** readmat(const char* filename, int * users, int* perms) {
    FILE* file = fopen(filename, "r");
    fscanf(file, "%d", users);
    fscanf(file, "%d", perms);
    int** upamat = upaspc(*users, *perms);
    int row, col;
    while (fscanf(file, "%d %d", &row, &col) == 2) {//as long as we can scan two consec ints, we set UPA mat to 1
        upamat[row - 1][col - 1] = 1; 
    }

    fclose(file);
    return upamat;
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
    return 0;
}
