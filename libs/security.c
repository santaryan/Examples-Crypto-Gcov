#include  <stdbool.h>
#include	<stdio.h>
#include	<stdlib.h>
#include  <sys/ioctl.h>
#include	<sys/types.h>
#include	<sys/wait.h>
#include	<string.h>
#include  <termios.h>
#include	<unistd.h>
#include  <crypt.h>

#include	"security.h"
#include  "cJSON.h"

#define LOGIN_LINE_LEN 255

unsigned long seed[2];
char salt[] = "$1$........";
const char *const seedchars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
														  
void readCommand(char buffer[]) {
  fgets(buffer, LOGIN_LINE_LEN, stdin);
  buffer[strlen(buffer)-1] = '\0';  // overwrite the line feed with null term
}

void generateSalt(void) {
  /* Generate a (not very) random seed.
    You should do it better than this... */
  seed[0] = time(NULL);
  seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);
  
  /* Turn it into printable characters from ‘seedchars’. */
  int i;
  for (i = 0; i < 8; i++)
  salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];
}

cJSON* loadUserDB(const char* userFile) { 
  char *strUserJson;
  long userDatabaseSize;  
  cJSON* d = NULL;
  FILE *fptrUserDatabase = fopen(userFile, "rb");
  if (fptrUserDatabase) {
    fseek(fptrUserDatabase, 0, SEEK_END);
    userDatabaseSize = ftell(fptrUserDatabase);
    fseek(fptrUserDatabase, 0, SEEK_SET);

    strUserJson = malloc(userDatabaseSize + 1);
    fread(strUserJson, userDatabaseSize, 1, fptrUserDatabase);
    fclose(fptrUserDatabase);

    strUserJson[userDatabaseSize] = 0;
    
    if (userDatabaseSize > 0) d = cJSON_Parse(strUserJson);
  }
  
  if (!d) d = cJSON_CreateObject();
  
	return d;
}

bool saveUserDB(const char* userFile, cJSON* userDatabase) {
  bool rc = false;
  char *strUserJson = cJSON_Print(userDatabase);
  FILE *fptrUserDatabase = fopen(userFile, "wb+");
  if (fptrUserDatabase != NULL) {
    if (fputs (strUserJson, fptrUserDatabase) != EOF) {
      rc = true;
    }
    if (fclose (fptrUserDatabase) == EOF) rc = false;
  }
  return rc;
}

cJSON* authenticateUser(const char* userFile) {
	cJSON *userDatabase = NULL;
	cJSON *userObject   = NULL;
	cJSON *userRetObj   = NULL;
	cJSON *passwordObj  = NULL;
  bool userValid = false;
  int loginAttempts = 0;
  char commandLine[LOGIN_LINE_LEN];
	char username[LOGIN_LINE_LEN];
	char password[LOGIN_LINE_LEN];
  
  userDatabase = loadUserDB(userFile);
  if (!userDatabase) {
    return NULL;
  }
  printf("Please type a username: ");
  readCommand(username);
  userObject = cJSON_GetObjectItem(userDatabase, username);
  if (userObject) {
    printf("User Exists!\nPlease enter your password: ");
    passwordObj = cJSON_GetObjectItem(userObject, "password");
    while (true) {
      readCommand(commandLine);
      strcpy(password, commandLine);
      if (!strcmp(crypt(commandLine, passwordObj->valuestring), passwordObj->valuestring)) {
        userValid = true;
        break;
      } else if (loginAttempts < 2) {
        printf("Wrong password! %d attempt(s) left.\nPlease enter your password: ", 1 - loginAttempts);
      } else {
        printf("Wrong password!\nDo you want to reset your password (y)? ");
        readCommand(commandLine);
        if (!strcmp(commandLine, "y")) {
          cJSON *recovery = cJSON_GetObjectItem(userObject, "recovery");
          if (recovery && cJSON_GetArraySize(recovery) > 0) {          
            int promptNum;
            for (promptNum = 0; promptNum < cJSON_GetArraySize(recovery); promptNum++) {        
              cJSON *prompt = cJSON_GetArrayItem(recovery, promptNum);
              char *question = cJSON_GetObjectItem(prompt, "question")->valuestring;
              char *answer = cJSON_GetObjectItem(prompt, "answer")->valuestring;
              printf("Question %d: %s\nAnswer: ", promptNum+1, question);
              readCommand(commandLine);
              if (strcmp(answer, crypt(commandLine, answer))) {
                userValid = false;
                break;
              }
              userValid = true;
            }
            if (userValid) {
							char commandLine[LOGIN_LINE_LEN];
						  printf("Please type a new password: ");
						  readCommand(commandLine);
							generateSalt();
						  passwordObj = cJSON_CreateString(crypt(commandLine, salt));
						  cJSON_ReplaceItemInObject(userObject, "password", passwordObj);
						  saveUserDB(userFile, userDatabase);
            } else {
              printf("User recovery failed.\n");
            }
          } else {
            printf("User has no method of recovering password.\n");
          }
        }
        break;
      }	    
      loginAttempts++;
    }
  } else {
    userObject = cJSON_CreateObject();
    printf("User not found.\nCreating new User.\nPlease type a password: ");
    readCommand(commandLine);
    
    generateSalt();
    cJSON_AddStringToObject(userObject, "password", crypt(commandLine, salt)); 
    
    cJSON *recovery = cJSON_CreateArray();
    cJSON *prompt1  = cJSON_CreateObject();
    cJSON *prompt2  = cJSON_CreateObject();
    cJSON *prompt3  = cJSON_CreateObject();
    
    printf("Please enter password recovery question 1: ");
    readCommand(commandLine);
    cJSON_AddStringToObject(prompt1, "question", commandLine);    
    printf("Please enter password recovery response 1: ");
    readCommand(commandLine);
    generateSalt();
    cJSON_AddStringToObject(prompt1, "answer", crypt(commandLine, salt));    
    cJSON_AddItemToArray(recovery, prompt1);
    
    printf("Please enter password recovery question 2: ");    
    readCommand(commandLine);
    cJSON_AddStringToObject(prompt2, "question", commandLine);    
    printf("Please enter password recovery response 2: ");
    readCommand(commandLine);
    generateSalt();
    cJSON_AddStringToObject(prompt2, "answer", crypt(commandLine, salt));    
    cJSON_AddItemToArray(recovery, prompt2);
    
    printf("Please enter password recovery question 3: ");    
    readCommand(commandLine);
    cJSON_AddStringToObject(prompt3, "question", commandLine);    
    printf("Please enter password recovery response 3: ");
    readCommand(commandLine);
    generateSalt();
    cJSON_AddStringToObject(prompt3, "answer", crypt(commandLine, salt));    
    cJSON_AddItemToArray(recovery, prompt3);
    
    cJSON_AddItemToObject(userObject, "recovery", recovery);    
    cJSON_AddItemToObject(userDatabase, username, userObject);
    
    userValid = true;
  }
	saveUserDB(userFile, userDatabase);
	if (userValid) {
		userRetObj = cJSON_CreateObject();
		cJSON_AddStringToObject(userRetObj, "username", username);
		cJSON_AddStringToObject(userRetObj, "password", password);
		cJSON_AddItemToObject(userRetObj, "data", cJSON_Duplicate(userObject, 1));
  }
	cJSON_Delete(userDatabase);
  return userRetObj;
}

void updateUser(const char* userFile, cJSON* userObject) {
  cJSON *userDatabase = NULL;
  if (!userObject) return;
  cJSON* u = cJSON_Duplicate(userObject, 1);
  userDatabase = loadUserDB(userFile);
  cJSON *username = cJSON_GetObjectItem(u, "username");
  cJSON *data     = cJSON_GetObjectItem(u, "data");
  cJSON_ReplaceItemInObject(userDatabase, username->valuestring, data);
	saveUserDB(userFile, userDatabase);
	cJSON_Delete(userDatabase);
}
