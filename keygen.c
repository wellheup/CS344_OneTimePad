/*********************************************************************
** Program: keygen.c
** Author: Phillip Wellheuser
** Date: 12/6/19
** Description: Generates a string cipher code for the otp_enc and 
**		otp_enc programs
*********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
	srand(time(0));

	//test the number of characters enter into arg[1] for vaildity
	if (atoi(argv[1]) <= 0) {
		perror("Please enter a valid number of characters");
		exit(1);
	}

	//generate random character A-Z for each number
	for (int i = 0; i < atoi(argv[1]); i++) {
		int c = (rand() % (26 - 0 + 1)) + 0;
		c += 64;
		printf("%c", c);
	}
	printf("%c", '\n');
}
