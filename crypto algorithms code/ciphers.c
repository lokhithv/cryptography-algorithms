#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define MAX_SIZE 1000
#define ALPHABET_SIZE 26

void caesarCipher(char *text, int key);
void atbashCipher(char *text);
void augustCipher(char *text, int key);
void affineCipher(char *text, int a, int b);
void vigenereCipher(char *text, char *key);
void gronsfeldCipher(char *text, char *key);
void beaufortCipher(char *text, char *key);
void autoClaveCipher(char *text, char *key);
void ngramAnalysis(char *text, int n);
void hillCipher(char *text, int *key, int size);
void railFenceCipher(char *text, int rails);
void railFenceDecrypt(char *text, int rails);
void routeCipher(char *text, int rows, int cols);
void routeDecrypt(char *text, int rows, int cols);
void myszkowskiCipher(char *text, char *key);
void myszkowskiDecrypt(char *text, char *key);
int gcd(int a, int b);
int modInverse(int a, int m);
int mod(int a, int b);

int main() {
    char text[MAX_SIZE];
    char key[MAX_SIZE];
    int choice, caesarKey, augustKey, affineA, affineB;
    int hillKey[9], hillSize, railFenceRails, routeRows, routeCols;
    int ngramSize;
    char railFenceEncrypted[MAX_SIZE];
    char railFenceOriginal[MAX_SIZE];
    char routeOriginal[MAX_SIZE];
    char myszkowskiOriginal[MAX_SIZE];
    
    printf("Enter the text: ");
    fgets(text, MAX_SIZE, stdin);
    text[strcspn(text, "\n")] = 0;

    printf("\nChoose a cipher:\n");
    printf("1. Caesar Cipher\n");
    printf("2. Atbash Cipher\n");
    printf("3. August Cipher\n");
    printf("4. Affine Cipher\n");
    printf("5. Vigenere Cipher\n");
    printf("6. Gronsfeld Cipher\n");
    printf("7. Beaufort Cipher\n");
    printf("8. AutoClave/Running Key Cipher\n");
    printf("9. N-gram Analysis\n");
    printf("10. Hill Cipher\n");
    printf("11. Rail Fence Cipher\n");
    printf("12. Route Cipher\n");
    printf("13. Myszkowski Cipher\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);
    getchar();

    switch (choice) {
        case 1:
            printf("Enter the key (shift value): ");
            scanf("%d", &caesarKey);
            char caesarOriginal[MAX_SIZE];
            strcpy(caesarOriginal, text);
            
            printf("\nEncryption:\n");
            caesarCipher(text, caesarKey);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            caesarCipher(text, 26 - (caesarKey % 26));
            printf("Decrypted text: %s\n", text);
            break;
            
        case 2:
            printf("\nEncryption:\n");
            char atbashOriginal[MAX_SIZE];
            strcpy(atbashOriginal, text);
            
            atbashCipher(text);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            atbashCipher(text);
            printf("Decrypted text: %s\n", text);
            break;
            
        case 3:
            printf("Enter the key (shift value): ");
            scanf("%d", &augustKey);
            char augustOriginal[MAX_SIZE];
            strcpy(augustOriginal, text);
            
            printf("\nEncryption:\n");
            augustCipher(text, augustKey);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            augustCipher(text, -augustKey);
            printf("Decrypted text: %s\n", text);
            break;
            
        case 4:
            printf("Enter the key a: ");
            scanf("%d", &affineA);
            printf("Enter the key b: ");
            scanf("%d", &affineB);
            char affineOriginal[MAX_SIZE];
            strcpy(affineOriginal, text);
            
            if(gcd(affineA, 26) != 1) {
                printf("Key 'a' must be coprime with 26\n");
                return 1;
            }
            
            printf("\nEncryption:\n");
            affineCipher(text, affineA, affineB);
            printf("Encrypted text: %s\n", text);
            
            char affineEncrypted[MAX_SIZE];
            strcpy(affineEncrypted, text);
            strcpy(text, affineOriginal);
            
            printf("\nDecryption:\n");
            int aInverse = modInverse(affineA, 26);
            affineCipher(affineEncrypted, aInverse, (-aInverse * affineB) % 26);
            printf("Decrypted text: %s\n", affineEncrypted);
            break;
            
        case 5:
            printf("Enter the key: ");
            fgets(key, MAX_SIZE, stdin);
            key[strcspn(key, "\n")] = 0;
            char vigenereOriginal[MAX_SIZE];
            strcpy(vigenereOriginal, text);
            
            printf("\nEncryption:\n");
            vigenereCipher(text, key);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            for(int i = 0; i < strlen(key); i++) {
                key[i] = (ALPHABET_SIZE - (key[i] - 'A')) % ALPHABET_SIZE + 'A';
            }
            vigenereCipher(text, key);
            printf("Decrypted text: %s\n", text);
            break;
            
        case 6:
            printf("Enter the numeric key: ");
            fgets(key, MAX_SIZE, stdin);
            key[strcspn(key, "\n")] = 0;
            char gronsfeldOriginal[MAX_SIZE];
            strcpy(gronsfeldOriginal, text);
            
            printf("\nEncryption:\n");
            gronsfeldCipher(text, key);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            for(int i = 0; i < strlen(key); i++) {
                key[i] = ((10 - (key[i] - '0')) % 10) + '0';
            }
            gronsfeldCipher(text, key);
            printf("Decrypted text: %s\n", text);
            break;
            
        case 7:
            printf("Enter the key: ");
            fgets(key, MAX_SIZE, stdin);
            key[strcspn(key, "\n")] = 0;
            char beaufortOriginal[MAX_SIZE];
            strcpy(beaufortOriginal, text);
            
            printf("\nEncryption:\n");
            beaufortCipher(text, key);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            beaufortCipher(text, key);
            printf("Decrypted text: %s\n", text);
            break;
            
        case 8:
            printf("Enter the key: ");
            fgets(key, MAX_SIZE, stdin);
            key[strcspn(key, "\n")] = 0;
            char autoClaveOriginal[MAX_SIZE];
            strcpy(autoClaveOriginal, text);
            
            printf("\nEncryption:\n");
            autoClaveCipher(text, key);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            // Perform decryption
            char decrypted[MAX_SIZE];
            int keyLen = strlen(key);
            char fullKey[MAX_SIZE];
            strcpy(fullKey, key);
            
            // Decrypt characters one by one
            for(int i = 0; i < strlen(text); i++) {
                if(isalpha(text[i])) {
                    char base = isupper(text[i]) ? 'A' : 'a';
                    int shift = toupper(fullKey[i]) - 'A';
                    // Reverse the encryption formula
                    decrypted[i] = ((text[i] - base - shift + ALPHABET_SIZE) % ALPHABET_SIZE) + base;
                    
                    // Extend key with decrypted plaintext if needed
                    if(i >= keyLen && i < strlen(text)) {
                        fullKey[i] = decrypted[i];
                    }
                } else {
                    decrypted[i] = text[i];
                }
            }
            decrypted[strlen(text)] = '\0';
            printf("Decrypted text: %s\n", decrypted);
            break;
            
        case 9:
            printf("Enter n for n-gram analysis: ");
            scanf("%d", &ngramSize);
            printf("\nN-gram Analysis (n=%d):\n", ngramSize);
            ngramAnalysis(text, ngramSize);
            break;
            
        case 10:
            printf("Enter matrix size (2 or 3): ");
            scanf("%d", &hillSize);
            
            if(hillSize != 2 && hillSize != 3) {
                printf("Only 2x2 or 3x3 matrices are supported\n");
                return 1;
            }
            
            printf("Enter %d matrix elements:\n", hillSize * hillSize);
            for(int i = 0; i < hillSize * hillSize; i++) {
                scanf("%d", &hillKey[i]);
            }
            
            char hillOriginal[MAX_SIZE];
            strcpy(hillOriginal, text);
            
            printf("\nEncryption:\n");
            hillCipher(text, hillKey, hillSize);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            int detMod;
            if(hillSize == 2) {
                detMod = mod(hillKey[0] * hillKey[3] - hillKey[1] * hillKey[2], 26);
            } else {
                detMod = mod(hillKey[0] * (hillKey[4] * hillKey[8] - hillKey[5] * hillKey[7]) -
                        hillKey[1] * (hillKey[3] * hillKey[8] - hillKey[5] * hillKey[6]) +
                        hillKey[2] * (hillKey[3] * hillKey[7] - hillKey[4] * hillKey[6]), 26);
            }
            
            int detInv = modInverse(detMod, 26);
            if(detInv == -1) {
                printf("Matrix is not invertible\n");
                return 1;
            }
            
            int adjoint[9];
            if(hillSize == 2) {
                adjoint[0] = hillKey[3];
                adjoint[1] = -hillKey[1];
                adjoint[2] = -hillKey[2];
                adjoint[3] = hillKey[0];
            } else {
                adjoint[0] = hillKey[4] * hillKey[8] - hillKey[5] * hillKey[7];
                adjoint[1] = -(hillKey[3] * hillKey[8] - hillKey[5] * hillKey[6]);
                adjoint[2] = hillKey[3] * hillKey[7] - hillKey[4] * hillKey[6];
                adjoint[3] = -(hillKey[1] * hillKey[8] - hillKey[2] * hillKey[7]);
                adjoint[4] = hillKey[0] * hillKey[8] - hillKey[2] * hillKey[6];
                adjoint[5] = -(hillKey[0] * hillKey[7] - hillKey[1] * hillKey[6]);
                adjoint[6] = hillKey[1] * hillKey[5] - hillKey[2] * hillKey[4];
                adjoint[7] = -(hillKey[0] * hillKey[5] - hillKey[2] * hillKey[3]);
                adjoint[8] = hillKey[0] * hillKey[4] - hillKey[1] * hillKey[3];
            }
            
            int inverse[9];
            for(int i = 0; i < hillSize * hillSize; i++) {
                inverse[i] = mod(adjoint[i] * detInv, 26);
            }
            
            hillCipher(text, inverse, hillSize);
            printf("Decrypted text: %s\n", text);
            break;
            
        case 11:
            printf("Enter number of rails: ");
            scanf("%d", &railFenceRails);
            strcpy(railFenceOriginal, text);
            
            printf("\nEncryption:\n");
            railFenceCipher(text, railFenceRails);
            printf("Encrypted text: %s\n", text);
            
            strcpy(railFenceEncrypted, text);
            strcpy(text, railFenceOriginal);
            
            printf("\nDecryption:\n");
            railFenceDecrypt(railFenceEncrypted, railFenceRails);
            printf("Decrypted text: %s\n", railFenceEncrypted);
            break;
            
        case 12:
            printf("Enter number of rows: ");
            scanf("%d", &routeRows);
            printf("Enter number of columns: ");
            scanf("%d", &routeCols);
            strcpy(routeOriginal, text);
            
            printf("\nEncryption:\n");
            routeCipher(text, routeRows, routeCols);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            routeDecrypt(text, routeRows, routeCols);
            printf("Decrypted text: %s\n", text);
            break;
            
        case 13:
            printf("Enter the key: ");
            fgets(key, MAX_SIZE, stdin);
            key[strcspn(key, "\n")] = 0;
            strcpy(myszkowskiOriginal, text);
            
            printf("\nEncryption:\n");
            myszkowskiCipher(text, key);
            printf("Encrypted text: %s\n", text);
            
            printf("\nDecryption:\n");
            myszkowskiDecrypt(text, key);
            printf("Decrypted text: %s\n", text);
            break;
            
        default:
            printf("Invalid choice!\n");
            return 1;
    }
    
    return 0;
}

void caesarCipher(char *text, int key) {
    for(int i = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            text[i] = ((text[i] - base + key) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE + base;
        }
    }
}

void atbashCipher(char *text) {
    for(int i = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            text[i] = base + (ALPHABET_SIZE - 1) - (text[i] - base);
        }
    }
}

void augustCipher(char *text, int key) {
    for(int i = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            int position = text[i] - base;
            position = (position * position) + key;
            position = ((position % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
            text[i] = base + position;
        }
    }
}

void affineCipher(char *text, int a, int b) {
    for(int i = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            text[i] = ((a * (text[i] - base) + b) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE + base;
        }
    }
}

void vigenereCipher(char *text, char *key) {
    int keyLen = strlen(key);
    for(int i = 0, j = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            int shift = toupper(key[j % keyLen]) - 'A';
            text[i] = ((text[i] - base + shift) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE + base;
            j++;
        }
    }
}

void gronsfeldCipher(char *text, char *key) {
    int keyLen = strlen(key);
    for(int i = 0, j = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            int shift = key[j % keyLen] - '0';
            text[i] = ((text[i] - base + shift) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE + base;
            j++;
        }
    }
}

void beaufortCipher(char *text, char *key) {
    int keyLen = strlen(key);
    for(int i = 0, j = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            int keyChar = toupper(key[j % keyLen]) - 'A';
            int plainChar = toupper(text[i]) - 'A';
            text[i] = ((keyChar - plainChar) % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE + base;
            j++;
        }
    }
}

void autoClaveCipher(char *text, char *key) {
    int textLen = strlen(text);
    int keyLen = strlen(key);
    char fullKey[MAX_SIZE];
    strcpy(fullKey, key);
    
    
    int k = keyLen;
    for(int i = 0; i < textLen - keyLen; i++) {
        fullKey[k++] = text[i];
    }
    fullKey[k] = '\0';
    
    
    for(int i = 0, j = 0; text[i] != '\0'; i++) {
        if(isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            int shift = toupper(fullKey[j]) - 'A';
            text[i] = ((text[i] - base + shift) % ALPHABET_SIZE) + base;
            j++;
        }
    }
}

void ngramAnalysis(char *text, int n) {
    int textLen = strlen(text);
    if(textLen < n) {
        printf("Text length is less than n\n");
        return;
    }
    
    int count[MAX_SIZE][2] = {0};
    int uniqueCount = 0;
    
    for(int i = 0; i <= textLen - n; i++) {
        char ngram[MAX_SIZE];
        strncpy(ngram, &text[i], n);
        ngram[n] = '\0';
        
        int found = 0;
        for(int j = 0; j < uniqueCount; j++) {
            char temp[MAX_SIZE];
            strncpy(temp, &text[count[j][0]], n);
            temp[n] = '\0';
            
            if(strcmp(ngram, temp) == 0) {
                count[j][1]++;
                found = 1;
                break;
            }
        }
        
        if(!found) {
            count[uniqueCount][0] = i;
            count[uniqueCount][1] = 1;
            uniqueCount++;
        }
    }
    
    for(int i = 0; i < uniqueCount; i++) {
        char ngram[MAX_SIZE];
        strncpy(ngram, &text[count[i][0]], n);
        ngram[n] = '\0';
        printf("%s: %d occurrences\n", ngram, count[i][1]);
    }
}

void hillCipher(char *text, int *key, int size) {
    int textLen = strlen(text);
    char result[MAX_SIZE];
    int paddingNeeded = 0;
    
    if(textLen % size != 0) {
        paddingNeeded = size - (textLen % size);
        for(int i = 0; i < paddingNeeded; i++) {
            text[textLen + i] = 'X';
        }
        text[textLen + paddingNeeded] = '\0';
        textLen += paddingNeeded;
    }
    
    for(int i = 0; i < textLen; i += size) {
        int vector[3] = {0};
        for(int j = 0; j < size; j++) {
            if(isalpha(text[i + j])) {
                vector[j] = toupper(text[i + j]) - 'A';
            }
        }
        
        for(int j = 0; j < size; j++) {
            int sum = 0;
            for(int k = 0; k < size; k++) {
                sum += key[j * size + k] * vector[k];
            }
            result[i + j] = (sum % 26) + 'A';
        }
    }
    
    result[textLen] = '\0';
    strcpy(text, result);
}

void railFenceCipher(char *text, int rails) {
    int textLen = strlen(text);
    char railMatrix[MAX_SIZE][MAX_SIZE];
    
    for(int i = 0; i < rails; i++) {
        for(int j = 0; j < textLen; j++) {
            railMatrix[i][j] = '.';
        }
    }
    
    int row = 0;
    int dir = 1;
    
    for(int i = 0; i < textLen; i++) {
        railMatrix[row][i] = text[i];
        row += dir;
        
        if(row == 0 || row == rails - 1) {
            dir = -dir;
        }
    }
    
    int index = 0;
    for(int i = 0; i < rails; i++) {
        for(int j = 0; j < textLen; j++) {
            if(railMatrix[i][j] != '.') {
                text[index++] = railMatrix[i][j];
            }
        }
    }
    text[index] = '\0';
}

void railFenceDecrypt(char *text, int rails) {
    int textLen = strlen(text);
    char railMatrix[MAX_SIZE][MAX_SIZE];
    
    for(int i = 0; i < rails; i++) {
        for(int j = 0; j < textLen; j++) {
            railMatrix[i][j] = '.';
        }
    }
    
    int row = 0;
    int dir = 1;
    
    for(int j = 0; j < textLen; j++) {
        railMatrix[row][j] = '*';
        row += dir;
        if(row == 0 || row == rails - 1) {
            dir = -dir;
        }
    }
    
    int index = 0;
    for(int i = 0; i < rails; i++) {
        for(int j = 0; j < textLen; j++) {
            if(railMatrix[i][j] == '*' && index < textLen) {
                railMatrix[i][j] = text[index++];
            }
        }
    }
    
    row = 0;
    dir = 1;
    char result[MAX_SIZE];
    
    for(int j = 0; j < textLen; j++) {
        result[j] = railMatrix[row][j];
        row += dir;
        if(row == 0 || row == rails - 1) {
            dir = -dir;
        }
    }
    result[textLen] = '\0';
    strcpy(text, result);
}

void routeCipher(char *text, int rows, int cols) {
    int textLen = strlen(text);
    char grid[MAX_SIZE][MAX_SIZE];
    
    for(int i = 0; i < rows; i++) {
        for(int j = 0; j < cols; j++) {
            int index = i * cols + j;
            grid[i][j] = (index < textLen) ? text[index] : ' ';
        }
    }
    
    int index = 0;
    char result[MAX_SIZE];
    
    for(int j = 0; j < cols; j++) {
        for(int i = 0; i < rows; i++) {
            result[index++] = grid[i][j];
        }
    }
    
    result[index] = '\0';
    strcpy(text, result);
}

void routeDecrypt(char *text, int rows, int cols) {
    int textLength = strlen(text);
    char grid[MAX_SIZE][MAX_SIZE];
    
    int k = 0;
    for(int j = 0; j < cols; j++) {
        for(int i = 0; i < rows; i++) {
            if(k < textLength) {
                grid[i][j] = text[k++];
            } else {
                grid[i][j] = ' ';
            }
        }
    }
    
    k = 0;
    char result[MAX_SIZE];
    for(int i = 0; i < rows; i++) {
        for(int j = 0; j < cols; j++) {
            result[k++] = grid[i][j];
        }
    }
    result[k] = '\0';
    strcpy(text, result);
}

void myszkowskiCipher(char *text, char *key) {
    int textLen = strlen(text);
    int keyLen = strlen(key);
    char keyOrder[MAX_SIZE];
    int col[MAX_SIZE];
    
    for(int i = 0; i < keyLen; i++) {
        keyOrder[i] = key[i];
        col[i] = i;
    }
    
    for(int i = 0; i < keyLen - 1; i++) {
        for(int j = 0; j < keyLen - i - 1; j++) {
            if(keyOrder[j] > keyOrder[j + 1]) {
                char tempCh = keyOrder[j];
                keyOrder[j] = keyOrder[j + 1];
                keyOrder[j + 1] = tempCh;
                
                int temp = col[j];
                col[j] = col[j + 1];
                col[j + 1] = temp;
            }
        }
    }
    
    int rows = (textLen + keyLen - 1) / keyLen;
    char grid[MAX_SIZE][MAX_SIZE];
    
    for(int i = 0; i < rows; i++) {
        for(int j = 0; j < keyLen; j++) {
            int index = i * keyLen + j;
            grid[i][j] = (index < textLen) ? text[index] : ' ';
        }
    }
    
    char result[MAX_SIZE];
    int index = 0;
    
    char currentChar = keyOrder[0];
    for(int k = 0; k < keyLen; k++) {
        for(int j = 0; j < keyLen; j++) {
            if(key[col[j]] == currentChar) {
                for(int i = 0; i < rows; i++) {
                    if(grid[i][col[j]] != ' ') {
                        result[index++] = grid[i][col[j]];
                    }
                }
            }
        }
        
        if(k < keyLen - 1) {
            currentChar = keyOrder[k + 1];
        }
    }
    
    result[index] = '\0';
    strcpy(text, result);
}

void myszkowskiDecrypt(char *text, char *key) {
    int len = strlen(text);
    int keyLen = strlen(key);
    int col[MAX_SIZE], order[MAX_SIZE];
    
    for(int i = 0; i < keyLen; i++) {
        col[i] = i;
    }
    
    for(int i = 0; i < keyLen; i++) {
        for(int j = i + 1; j < keyLen; j++) {
            if(key[i] > key[j]) {
                char tempCh = key[i];
                key[i] = key[j];
                key[j] = tempCh;
                
                int temp = col[i];
                col[i] = col[j];
                col[j] = temp;
            }
        }
    }
    
    for(int i = 0; i < keyLen; i++) {
        order[col[i]] = i;
    }
    
    int rows = (len + keyLen - 1) / keyLen;
    char grid[MAX_SIZE][MAX_SIZE];
    
    for(int i = 0; i < rows; i++) {
        for(int j = 0; j < keyLen; j++) {
            grid[i][j] = ' ';
        }
    }
    
    int pos = 0;
    for(int j = 0; j < keyLen; j++) {
        int currCol = col[j];
        int charsInCol = (currCol < len % keyLen) ? rows : (len / keyLen);
        
        if(len % keyLen == 0 || currCol >= len % keyLen) {
            charsInCol = len / keyLen;
        } else {
            charsInCol = len / keyLen + 1;
        }
        
        for(int i = 0; i < charsInCol; i++) {
            grid[i][order[currCol]] = text[pos++];
        }
    }
    
    char result[MAX_SIZE];
    int index = 0;
    
    for(int i = 0; i < rows; i++) {
        for(int j = 0; j < keyLen; j++) {
            if(grid[i][j] != ' ') {
                result[index++] = grid[i][j];
            }
        }
    }
    
    result[index] = '\0';
    strcpy(text, result);
}

int gcd(int a, int b) {
    a = abs(a);
    b = abs(b);
    while(b) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int modInverse(int a, int m) {
    a = ((a % m) + m) % m;
    for(int x = 1; x < m; x++) {
        if((a * x) % m == 1) {
            return x;
        }
    }
    return -1;
}

int mod(int a, int b) {
    int result = a % b;
    return result >= 0 ? result : result + b;
}
