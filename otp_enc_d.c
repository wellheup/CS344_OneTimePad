
/*********************************************************************
** Program: otp_enc_d.c
** Author: Phillip Wellheuser
** Date: 12/6/19
** Description: Presents 5 sockets through which processes may connect
**		and request encryption of a plain text using a cipher text
*********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <ctype.h>

//prototypes
void EncryptMsg(int childSocket);
int Handshake(int childSocket);


void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

/*********************************************************************
** Description: Manages sockets and forked child processes, each of which
**		can receive and process an encryption request
*********************************************************************/
int main(int argc, char *argv[]) {
	int listenSocketFD, portNumber;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr, "USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process 

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) 
		error("SERVER: ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("SERVER: ERROR on binding");
	
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	pid_t parentPID = getpid();
	int numChildSockets = 0;
	int connectedChildSocketFD;
	int numChildProcs = 0;
	int childProcs[5];
	while (parentPID == getpid()) {
		if (numChildProcs > 0) {
			for (int i = 0; i < numChildProcs; i++) {
				int curChildStatus;
				pid_t curChild = waitpid(childProcs[i], &curChildStatus, WNOHANG);
				if (curChild != 0) {
					//say something about the child
					char errMsg[1000];
					if (WIFEXITED(curChildStatus) != 0) {//if proc term'd naturally
						sprintf(errMsg, "SERVER: child pid %d is done: exit value %d\n", curChild, WEXITSTATUS(curChildStatus));
						//perror(errMsg);
					}
					if (WIFSIGNALED(curChildStatus) != 0) {//if prok term'd by signal
						sprintf(errMsg, "SERVER: child pid %d is done: terminated by signal %d\n", curChild, WTERMSIG(curChildStatus));
						//perror(errMsg);
					}

					//replace the child with the most recent child
					childProcs[i] = childProcs[numChildProcs - 1];
					numChildProcs--;
					numChildSockets--;
				}
			}
		}
		if (numChildSockets < 5) {
			// Accept a connection, blocking if one is not available until one connects
			sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
			connectedChildSocketFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
			if (connectedChildSocketFD < 0) error("SERVER: ERROR on accept");

			pid_t spawnPid = fork();
			switch (spawnPid) {
			case 0://this is the child process
				if (Handshake(connectedChildSocketFD) == 1) {
					EncryptMsg(connectedChildSocketFD);
					close(connectedChildSocketFD); // Close the existing socket which is connected to the client
				}
				else {
					close(connectedChildSocketFD); // Close the existing socket which is connected to the client
					error("SERVER: client failed handshake, terminating encryption");
				}
				return 0;
				break;
			case -1://something has gone terribly wrong
				error("SERVER: failed to fork: ");
				return -1;
				break;
			default://this is the parent process
				numChildSockets++;
				childProcs[numChildProcs] = spawnPid;
				numChildProcs++;
				break;
			}
		}
		else {
			//waiting for a child to finish and release a socket
		}

	}
	close(listenSocketFD); // Close the listening socket		

	return 0;
}

/*********************************************************************
** Description: Exchanges basic string messages with otp_enc
**		to determine that it has connected to the correct program
*********************************************************************/
int Handshake(int childSocket) {
	// Get the message from the client
	char buffer[1024];
	memset(buffer, '\0', 1024);
	char* progName = "otp_enc_d";
	char* clientName = "otp_enc";
	int charsRead;
	int curChar = 0;

	charsRead = recv(childSocket, buffer, 1023, 0); // Read the client's message from the socket
	if (charsRead < 0) error("SERVER: ERROR reading from socket");//check  to make sure right # bytes were read

	if (strcmp(buffer, clientName) == 0) {
		// Send a Success message back to the client
		do {
			charsRead = send(childSocket, progName + curChar, strlen(progName), 0); // Send success back
			if (charsRead < 0) error("SERVER: ERROR writing id message to socket");
			if (charsRead <= strlen(progName) && charsRead >= 0) {
				curChar += charsRead;
			}
		} while (charsRead < strlen(progName));
		return 1;
	}
	else {
		// Send a bogus message to tell client to kill itself
		curChar = 0;
		do {
			charsRead = send(childSocket, "no", 2, 0); // Send success back
			if (charsRead < 0) error("SERVER: ERROR writing id message to socket");
			if (charsRead <= 2 && charsRead >= 0) {
				curChar += charsRead;
			}
		} while (charsRead < 2);
	}
	return 0;
}

/*********************************************************************
** Description: Receives and encrypts a message
*********************************************************************/
void EncryptMsg(int childSocket) {
	char buffer[1024];
	memset(buffer, '\0', 1024); 
	char* plainText;
	int plainTextSize;
	char* key;
	int keySize;
	char* plainTextReq = "sendPlainText";
	char* keyReq = "sendKey";
	int charsRead;
	int curChar;

	//get plainText Size from client
	charsRead = recv(childSocket, buffer, 1023, 0); // Read the client's plainText
	if (charsRead < 0) error("SERVER: ERROR reading plainTextSize from socket");//check  to make sure right # bytes were read

	//resize plainText and key to accomodate incoming text size
	plainTextSize = atoi(buffer) + 1;
	plainText = (char *)malloc((plainTextSize) * sizeof(char));
	memset(plainText, '\0', plainTextSize);
	key = (char *)malloc((plainTextSize) * sizeof(char));
	memset(key, '\0', plainTextSize);

	//request plainText from client
	curChar = 0;
	do {
		charsRead = send(childSocket, plainTextReq + curChar, strlen(plainTextReq), 0); // Send request for key
		if (charsRead < 0) error("SERVER: ERROR writing key request to socket");
		if (charsRead <= strlen(plainTextReq) && charsRead >= 0) {
			curChar += charsRead;
		}
	} while (curChar < strlen(plainTextReq));

	//get plainText msg from client
	charsRead = recv(childSocket, plainText, plainTextSize-1, 0); // Read the client's plainText
	if (charsRead < 0) error("SERVER: ERROR reading plainText from socket");//check  to make sure right # bytes were read
																			
	//request key from client
	curChar = 0;
	do {
		charsRead = send(childSocket, keyReq + curChar, strlen(keyReq), 0); // Send request for key
		if (charsRead < 0) error("SERVER: ERROR writing key request to socket");
		if (charsRead <= strlen(keyReq) && charsRead >= 0) {
			curChar += charsRead;
		}
	} while (curChar < strlen(keyReq));

	//get key from client
	charsRead = recv(childSocket, key, plainTextSize-1, 0); // Read the client's key
	if (charsRead < 0) error("SERVER: ERROR reading from socket");//check  to make sure right # bytes were read

	for (int i = 0; i < strlen(plainText); i++) {//encrypt the plainText
		if (isupper(plainText[i]) != 0) {
			plainText[i] -= 64;
			plainText[i] += key[i] - 64;
			plainText[i] = plainText[i] % 27;
			plainText[i] += 64;
		}
		else if (plainText[i] == ' ') {
			plainText[i] = 0;
			plainText[i] += key[i] - 64;
			plainText[i] = plainText[i] % 27;
			plainText[i] += 64;
		}
		else if (plainText[i] == '\n') {
			//plainText[i] = '\0';
			break;
		}
		else if (plainText[i] == '\0') {
			plainText[i] = '\n';
			break;
		}
		else {
		}
	}

	//send encrypted text back to client
	curChar = 0;
	do {
		charsRead = send(childSocket, plainText + curChar, strlen(plainText), 0); // Return the encrypted text
		if (charsRead < 0) error("SERVER: ERROR writing to socket");
		if (charsRead <= strlen(plainText) && charsRead >= 0) {
			curChar += charsRead;
		}
	} while (curChar < strlen(plainText));
}