#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "./libs/security.h"
#include "./libs/cJSON.h"
#include "./libs/encryption.h"

#define FILENAME ".users"
#define LINE_LEN 255

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
  cJSON *userObject = NULL;
  char *password;
  char *fileInputTemp, *fileInput, *fileOutput;
  char filenameIn[LINE_LEN];
  char filenameOut[LINE_LEN];
  int filenameLen, passLen, fileLen;
  
  userObject = authenticateUser(FILENAME);
  if (!userObject) {
    printf("error\n");
		exit(EXIT_FAILURE); 
  } else {
		printf("Authenticated\n");
  }
    
	password = cJSON_GetObjectItem(userObject, "password")->valuestring; // password->valuestring
  passLen = strlen(password);
  
  while (1) {
	  printf("Please enter the filename that you wish to run encryption on (.crpt files will decrypt): ");
	  readCommand(filenameIn);
	  filenameLen = strlen(filenameIn);	  
	  if (filenameLen < 1) break; 
	  
	  fileInputTemp = readFile(filenameIn);
	  fileLen = strlen(fileInputTemp);
	  
	  fileInput  = (char*) malloc(passLen + fileLen + 1); 
	  fileOutput = (char*) malloc(passLen + fileLen + 1); 
	  
	  if (strstr(filenameIn, "crpt" )) {
	    printf("Running decryption protocol!\n");
			strcpy(fileInput, fileInputTemp);
			XORCrypt(fileInput, fileOutput, password);			
		  strcpy(fileInput, fileOutput);	
		  subDecodeString(fileInput, fileOutput, 6); 		  		
			strcpy(fileInput, fileOutput);
	    transDecodeString(fileInput, fileOutput);	    
	    memset(fileInput, 0, passLen+1);
	    strncpy(fileInput, fileOutput, passLen);
	    if (strcmp(fileInput, password)) {
	      printf("This file cannot be decrypted with your password. You do not have authority!\n");
	    } else {
		    memset(filenameOut, 0, filenameLen);
		    strncpy(filenameOut, filenameIn, filenameLen-5);
			  writeFile(filenameOut, &fileOutput[passLen]);
			  remove(filenameIn);
	    }
		} else {
	    printf("Running Encryption protocol!\n");
			sprintf(fileInput, "%s%s", password, fileInputTemp);    
	    transEncodeString(fileInput, fileOutput);
		  strcpy(fileInput, fileOutput);	  
		  subEncodeString(fileInput, fileOutput, 6); 		  
		  strcpy(fileInput, fileOutput);	  
		  XORCrypt(fileInput, fileOutput, password);		  		  	  
		  sprintf(filenameOut, "%s.crpt", filenameIn);
		  writeFile(filenameOut, fileOutput);
		  remove(filenameIn);
    }
		free (fileInputTemp);
		free (fileInput);
		free (fileOutput);
  }
	exit(EXIT_SUCCESS); 
}