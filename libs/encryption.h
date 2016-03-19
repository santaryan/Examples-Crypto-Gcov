void XORCrypt(char input[], char output[], char key[]);

char subEncodeChar(char ch, int rotate);

void subEncodeString(char input[], char output[], int rotate);

char subDecodeChar(char ch, int rotate);

void subDecodeString(char input[], char output[], int rotate);

void transEncodeBlock(char input[], char output[], int trans[], int length);

void transDecodeBlock(char input[], char output[], int detrans[], int length);

void transEncodeString(char input[], char output[]);

void transDecodeString(char input[], char output[]);