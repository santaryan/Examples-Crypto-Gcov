#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <crypt.h>

#define BLOCK_SIZE (5)

//                         0  1  2  3  4
int trans[BLOCK_SIZE]   = {1, 4, 3, 0, 2};
int detrans[BLOCK_SIZE] = {3, 0, 4, 2, 1};

void XORCrypt(char input[], char output[], char key[]) {
  int inLen = strlen(input);
  int keyLen = strlen(key);
  int i;
	for (i = 0; i < inLen; i++)
		output[i] = input[i] ^ key[i%keyLen];
  
	output[i] = '\0';
}

char subEncodeChar(char ch, int rotate)
{
  return (char) ((ch-' '+(rotate%95))%95)+' ';
}

char subDecodeChar(char ch, int rotate)
{
  int d = (char) ((ch-' '-(rotate%95))%95);
  if (d < 0) return 127+d;
  return d+' ';
}

void subEncodeString(char input[], char output[], int rotate)
{
    int i, length = strlen(input);
    memset(output, 0, length);

    for (i = 0; i < length; i++) {
      output[i] = subEncodeChar(input[i], rotate);
    }
    output[i] = '\0';
}

void subDecodeString(char input[], char output[], int rotate)
{
    int i, length = strlen(input);
    memset(output, 0, length);

    for (i = 0; i < length; i++) {      
      output[i] = subDecodeChar(input[i], rotate);
    }
}

void transEncodeBlock(char input[], char output[], int transmap[], int length) {
    int i;
    char temp;

    for(i=0; i < length; i++) {
        output[i] = input[transmap[i]];
    }
}

void transDecodeBlock(char input[], char output[], int detransmap[], int length) {
    int i;
    char temp;

    for(i=0; i < length; i++) {
        output[i] = input[detransmap[i]];
    }
}

void transEncodeString(char input[], char output[]) {
    int idx=0;
    int length = strlen(input);
    
    memset(output, 0, length);
        
    do {
        if((length-idx) < BLOCK_SIZE) {
            strcpy(&output[idx], &input[idx]);
            break;
        } else {
					transEncodeBlock(&input[idx], &output[idx], trans, BLOCK_SIZE);
					idx += BLOCK_SIZE;
        }
    } while(idx < length);
}



void transDecodeString(char input[], char output[]) {
    int idx=0;
    int length = strlen(input);
    
    memset(output, 0, length);
    
    do {
        if((length-idx) < BLOCK_SIZE) {
            strcpy(&output[idx], &input[idx]);
            break;
        } else {
            transDecodeBlock(&input[idx], &output[idx], detrans, BLOCK_SIZE);
            idx += BLOCK_SIZE;
        }        
    } while(idx < length);    
}