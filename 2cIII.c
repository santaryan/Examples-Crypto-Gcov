#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

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

void fileCrypt(char* filenameIn, char* password) { 
  int fileLen;
  int filenameLen = strlen(filenameIn);
  int passLen = strlen(password); 
  char *fileInputTemp, *fileInput, *fileOutput;
  char filenameOut[LINE_LEN];
  
  fileInputTemp = readFile(filenameIn);
  fileLen = strlen(fileInputTemp);
  
  fileInput  = (char*) malloc(passLen + fileLen + 1); 
  fileOutput = (char*) malloc(passLen + fileLen + 1); 
    
  if (strstr(filenameIn, "crpt" )) {
    printf("Running decryption protocol on %s!\n", filenameIn);
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
      printf("File decrypted. Writing back data!\n");
      memset(filenameOut, 0, filenameLen);
      strncpy(filenameOut, filenameIn, filenameLen-5);
      writeFile(filenameOut, &fileOutput[passLen]);
      remove(filenameIn);
    }
  } else {
    printf("Running Encryption protocol on %s!\n", filenameIn);
    sprintf(fileInput, "%s%s", password, fileInputTemp);    
    transEncodeString(fileInput, fileOutput);
    strcpy(fileInput, fileOutput);	  
    subEncodeString(fileInput, fileOutput, 6); 		  
    strcpy(fileInput, fileOutput);	  
    XORCrypt(fileInput, fileOutput, password);		  		  	  
    sprintf(filenameOut, "%s.crpt", filenameIn);
    printf("File encrypted. Writing back data!\n");
    writeFile(filenameOut, fileOutput);
    remove(filenameIn);
  }
  free (fileInputTemp);
  free (fileInput);
  free (fileOutput);
}

void main() {
  cJSON *userObject = NULL;
  char *password;
  char filenameIn[LINE_LEN];
  int filenameLen;
  struct stat s;
  
  userObject = authenticateUser(FILENAME);
  if (!userObject) {
    printf("error\n");
    exit(EXIT_FAILURE); 
  } else {
    printf("Authenticated\n");
  }
  
  password = cJSON_GetObjectItem(userObject, "password")->valuestring; // password->valuestring
  
  while (1) {
    printf("Please enter the filename that you wish to run encryption on (.crpt files will decrypt): ");
    readCommand(filenameIn);
    filenameLen = strlen(filenameIn);	  
    if (filenameLen < 1) break;
    
    if( stat(filenameIn,&s) == 0 ) {
      if( s.st_mode & S_IFDIR ) {
        printf("You have entered a folder. Running protocols as needed on contents!\n");
        struct dirent *dp;
        DIR *dfd;

        char *dir = filenameIn;
        
        if (dfd = opendir(dir)) {          
          char filename_qfd[100] ;

          while ((dp = readdir(dfd)) != NULL) {
            struct stat stbuf ;
            sprintf( filename_qfd , "%s/%s",dir,dp->d_name) ;
            if( stat(filename_qfd,&stbuf ) == -1 ) {
              printf("Unable to stat file: %s\n",filename_qfd) ;
              continue ;
            }
            if ( ( stbuf.st_mode & S_IFMT ) == S_IFDIR ) {
              continue;
              // Skip directories
            } else {
              fileCrypt(filename_qfd, password);
            }
          }
        }
      } else if( s.st_mode & S_IFREG ) {
        fileCrypt(filenameIn, password);
      }      
    }
  }
  exit(EXIT_SUCCESS); 
}