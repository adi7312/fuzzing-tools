#include "coverage-rt.h"
#include <dirent.h>
#include <stdlib.h>

#define FILE_MODE 0
#define DIR_MODE 1
#define UNKNOWN 3

int getEntryType(const char* path){
    struct stat stats;
    if (stat(path, &stats) < 0){
        fprintf(stderr, "Entry does not exist");
        return -1;
    }
    if (S_ISDIR(stats.st_mode)) {
        return DIR_MODE;
    }
    else if (S_ISREG(stats.st_mode)){
        return FILE_MODE;
    }
    else {
        return UNKNOWN;
    }
}

void executeSingleTest(const char* path){
    struct stat stats;
    if (stat(path, &stats) < 0) {
        fprintf(stderr, "Failed to stat file: %s\n", path);
        return;
    }
    unsigned long fs = stats.st_size;

    FILE* fp = fopen(path, "r");
    if (fp == NULL){
        fprintf(stderr, "Failed to open file %s", path);
        return;
    }
    uint8_t* buffer = (uint8_t*) malloc(fs);
    if (buffer == NULL){
        fprintf(stderr, "malloc: could not allocate memory");
        fclose(fp);
        return;
    }

    unsigned long rs = fread(buffer, 1, fs, fp);
    if (rs != fs){
        free(buffer);
        fclose(fp);
        fprintf(stderr,"assertion error: fs != rs");
        return;
    }

    LLVMFuzzerTestOneInput(buffer,rs);
    free(buffer);
    fclose(fp);

}

int main(int argc, char* argv[]){
    int entryType = getEntryType(argv[1]);
    switch (entryType)
    {
    case DIR_MODE:
        DIR* dir = opendir(argv[1]);
        if (dir == NULL){
            fprintf(stderr, "Failed to open handle on a directory: %s",argv[1]);
            return 1;
        }
        struct dirent *entry;
        while ((entry = readdir(dir))){
            if (entry->d_type == DT_REG){
                size_t path_len = strlen(argv[1]) + strlen(entry->d_name) + 2;
                char *path = malloc(path_len);
                if (path == NULL) {
                    fprintf(stderr, "Failed to allocate memory for path\n");
                    closedir(dir);
                    return 1;
                }
                snprintf(path, path_len, "%s/%s", argv[1], entry->d_name);
                executeSingleTest(path);
                free(path);
            }
        }
        closedir(dir);
        break;
    case FILE_MODE:
        executeSingleTest(argv[1]);
        break;
    
    default:
        fprintf(stderr, "Usage: %s <directory/file>",argv[0]);
        return 1;
    }
    return 0;

}
