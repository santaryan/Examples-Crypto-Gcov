#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>

#include "./libs/encryption.h"

#define LOGIN_LINE_LEN 255

char* readFile(const char* file) { 
  long size;
  char* data = NULL;
  FILE *fptr = fopen(file, "rb");
  if (fptr) {
    fseek(fptr, 0, SEEK_END);
    size = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);

    data = malloc(size + 1);
    fread(data, size, 1, fptr);
    fclose(fptr);

    data[size] = 0;    
  }
  return data;
}

bool writeFile(const char* file, char* data) {
  bool rc = false;
  FILE *fptr = fopen(file, "wb+");
  if (fptr) {
    if (fputs (data, fptr) != EOF) {
      rc = true;
    }
    if (fclose (fptr) == EOF) rc = false;
  }
  return rc;
}

void main() {
  char *fileInput = NULL, *fileOutput = NULL;
  char filenameIn[LOGIN_LINE_LEN];
  char filenameOut[LOGIN_LINE_LEN];
  int fileSize;
  
  printf("Input filename to run through encryption test: ");
  readCommand(filenameIn);
  
  fileInput = readFile(filenameIn);
  fileOutput = malloc(strlen(fileInput) + 1);
    
  transEncodeString(fileInput, fileOutput);
  strcpy(fileInput, fileOutput);
  subEncodeString(fileInput, fileOutput, 6); 
  strcpy(fileInput, fileOutput);
  XORCrypt(fileInput, fileOutput, "HYiC5dZC0jiMdeQByHcPXxY7sDATnwyX");
  
  sprintf(filenameOut, "%s.crpt", filenameIn);
  writeFile(filenameOut, fileOutput);
  free(fileInput);

  fileInput = readFile(filenameIn);
  
  strcpy(fileInput, fileOutput);
  XORCrypt(fileInput, fileOutput, "HYiC5dZC0jiMdeQByHcPXxY7sDATnwyX");
  strcpy(fileInput, fileOutput);
  subDecodeString(fileInput, fileOutput, 6);
  strcpy(fileInput, fileOutput);
  transDecodeString(fileInput, fileOutput);
  
  sprintf(filenameOut, "%s.decrpt", filenameIn);
  writeFile(filenameOut, fileOutput);
  
  free(fileInput);
  free(fileOutput);
  
  fileInput = readFile(filenameIn);
  fileOutput = readFile(filenameOut);
  if (strcmp(fileInput, fileOutput)) {
    printf("Encryption failed!\n");
  } else {
    printf("Successfully encrypted and decrypted file!\n");
  }
  
  free(fileInput);
  free(fileOutput);
}