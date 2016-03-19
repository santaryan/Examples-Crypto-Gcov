#ifndef NULL
#define	NULL	0
#endif

#include <stdbool.h>

#include "cJSON.h"

cJSON* authenticateUser(const char* userFile);
void updateUser(const char* userFile, cJSON* userObject);
void readCommand(char buffer[]);
