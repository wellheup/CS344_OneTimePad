/*********************************************************************
** Program: otp_dec.c
** Author: Phillip Wellheuser
** Date: 12/6/19
** Description: Reads a plain text file and a cipher file and requests
**		the otp_enc_d server at the port provided to encrypt the text
**		then prints the result to stdout
*********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <ctype.h>

//prototypes
int Handshake(int socketFD);
char* ReqEncrypt(int socketFD, char* plainText, char* key);
int ValidateFiles(char* plainText, char* key);
char* ReadFile(char* inFileName);

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

/*********************************************************************
** Description: Connects to the server port provided and requests
**		encryption of provided files
*********************************************************************/
int main(int argc, char *argv[]) {
	//arg[3] = port
	char *plainText;
	char *key;
	plainText = ReadFile(argv[1]);
	key = ReadFile(argv[2]);
	if (ValidateFiles(plainText, key) != 1) {
		exit(1);
	}

	//connect to server
	int socketFD, portNumber;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[256];

	if (argc < 4) { fprintf(stderr, "CLIENT: USAGE: %s hostname port\n", "localhost"); exit(0); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host as %s\n", "localhost"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");

	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

	if (Handshake(socketFD) == 1) {
		plainText = ReqEncrypt(socketFD, plainText, key);
	}
	else {
		close(socketFD);
		fprintf(stderr, "CLIENT: Could not connect to port %s, terminating process.", argv[3]);
		exit(2);
	}

	//print the encrypted text
	printf("%s", plainText);
	close(socketFD); // Close the socket

	exit(0);
}

/*********************************************************************
** Description: Exchanges basic string messages with otp_enc_d server
**		to determine that it has connected to the correct program
*********************************************************************/
int Handshake(int socketFD) {
	char buffer[1024];
	char* progName = "otp_enc";
	char* encryptorName = "otp_enc_d";
	memset(buffer, '\0', 1024);
	int charsRead;
	int curChar = 0;

	do {
		// Send handshake to server
		charsRead = send(socketFD, progName + curChar, strlen(progName), 0); // Write to the server
		if (charsRead < 0) error("CLIENT: ERROR writing id message to socket");
		if (charsRead <= strlen(progName) && charsRead >= 0) {
			curChar += charsRead;
		}
	} while (curChar < strlen(progName));

	// Get get return handshake from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading from socket");

	//confirm encryptor identity
	if (strcmp(buffer, encryptorName) == 0) {
		return 1;
	}
	return 0;
}

/*********************************************************************
** Description: Sends otp_enc_d process that the program is connected
**		to a plain text string and a cipher code and then
**		receives the encrypted result
*********************************************************************/
char* ReqEncrypt(int socketFD, char* plainText, char* key) {
	char buffer[1024];
	memset(buffer, '\0', 1024);
	char plainTextSize[10];
	char* plainTextReq = "sendPlainText";
	char* keyReq = "sendKey";
	int charsRead;
	int curChar;

	// send size of plainText to server
	sprintf(plainTextSize, "%ld", strlen(plainText));
	curChar = 0;
	do {
		charsRead = send(socketFD, plainTextSize + curChar, strlen(plainTextSize), 0); // Write to the server
		if (charsRead < 0) error("CLIENT: ERROR writing plainText to socket");
		if (charsRead <= strlen(plainTextSize) && charsRead >= 0) {
			curChar += charsRead;
		}
	} while (curChar < strlen(plainTextSize));

	// get request for plainText
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading key request from socket");

	if (strcmp(buffer, plainTextReq) == 0) {
		// Send plainText to server
		curChar = 0;
		do {
			charsRead = send(socketFD, plainText + curChar, strlen(plainText), 0); // Write to the server
			if (charsRead < 0) error("CLIENT: ERROR writing plainText to socket");
			if (charsRead <= strlen(plainText) && charsRead >= 0) {
				curChar += charsRead;
			}
		} while (curChar < strlen(plainText));
	}
	else {
		error("CLIENT: server failed to request plainText properly\n");
	}

	// Get key request message from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
	if (charsRead < 0) error("CLIENT: ERROR reading key request from socket");

	if (strcmp(buffer, keyReq) == 0) {
		// Send key to server
		curChar = 0;
		do {
			charsRead = send(socketFD, key + curChar, strlen(plainText), 0); // Write to the server
			if (charsRead < 0) error("CLIENT: ERROR writing key to socket");
			if (charsRead <= strlen(plainText) && charsRead >= 0) {
				curChar += charsRead;
			}
		} while (curChar < strlen(plainText));
	}
	else {
		error("CLIENT: server failed to request key properly\n");
	}

	// Get the encrypted plainText from server
	charsRead = recv(socketFD, plainText, strlen(plainText), 0); // Read data from the socket

	return plainText;
}

/*********************************************************************
** Description: Reads a file by name and returns a string of the contents
*********************************************************************/
char* ReadFile(char* inFileName) {
	//get plainText file
	char* textIn;
	size_t textInSize = 32;
	size_t textInChars;
	FILE* textInFD = fopen(inFileName, "r");
	if (textInFD == NULL) {
		fprintf(stderr, "CLIENT: could not open file %s\n", inFileName);
	}
	//prepare var for text
	textIn = (char *)malloc(textInSize * sizeof(char));
	if (textIn == NULL) {
		error("CLIENT: unable to allocate space for input file");
	}

	textInChars = getline(&textIn, &textInSize, textInFD);
	if (textInChars == 0) {
		error("CLIENT: no message to read");
	}
	else if (textInChars == -1) {
		error("CLIENT: failed to read file");
	}

	return textIn;
}

/*********************************************************************
** Description: Scans the plain text and cipher text to ensure they
**		have valid contents for the program
*********************************************************************/
int ValidateFiles(char* plainText, char* key) {
	if (strlen(key) < strlen(plainText)) {
		fprintf(stderr, "CLIENT: key is too short for message\n");
		return 0;
	}
	for (int i = 0; i < strlen(plainText); i++) {
		//if neither space nor uppercase char nor newline
		if (plainText[i] == ' ' || isupper(plainText[i]) != 0 || plainText[i] == '\n') {
			//do nothing b/c valid
		}
		else {
			fprintf(stderr, "CLIENT: invalid characters detected in plainText");
			return 0;
		}
	}
	for (int i = 0; i < strlen(key); i++) {
		//if neither @ nor uppercase char nor newline
		if (key[i] == '@' || isupper(key[i]) != 0 || key[i] == '\n') {
			//do nothing b/c valid
		}
		else {
			fprintf(stderr, "CLIENT: invalid characters detected in key");
			return 0;
		}
	}
	return 1;
}
