#pragma once
#include <NTL/ZZ.h>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <iostream>
#include <time.h>
#include <stdlib.h>
#include "FFunction.h"
#include "GFunction.h"
#include "RevealedInformation.h"

#define PRIMES_LENGTH 10

#define INFORMATION "../OfficeServer/serverInfo.txt"

#define OK 0
#define INVALID 1
#define FRAUD 2

using namespace std;
using namespace NTL;

ZZ compositeNumber;
ZZ firstPrimeNumber, secondPrimeNumber;
ZZ privateKey;
int securityConstant;
map<ZZ, RevealedInformation> storedInformation;
map<ZZ, ZZ> impostors;

int positiveVotes = 0;
int negativeVotes = 0;

class Server {
private:

    static void sendNumberToClient(ZZ& number, int client);
	static ZZ receiveNumberFromClient(int client);
    static ZZ decryptMessageUsingCRT(ZZ blindMessage); // sign a single blinded message
	static void chooseRandomRequests(int* requests, int numberOfRequests);
	static bool verifyCorrectFunction(ZZ blindSignature, ZZ ID, ZZ a, ZZ c, ZZ d, ZZ r);
	static ZZ findNewInformationAndProduct(RevealedInformation& information, int* requests, int numberOfRequests, int client);
public:
	static void initialize();
    static void execute(int client);
};

void Server::initialize() {
	ifstream in("INFORMATION");
	in >> privateKey >> compositeNumber >> firstPrimeNumber >> secondPrimeNumber;
	in.close();
}

void Server::sendNumberToClient(ZZ& number, int client) {
    long numberLength = NumBytes(number);
    if(write(client, &numberLength, sizeof(long)) < 0) {
        perror("Error at writing number length to client.\n");
        exit(0);
    }
    unsigned char representation[numberLength + 1];
    BytesFromZZ(representation, number, numberLength);
    for(long i = 0; i < numberLength; ++i) {
        if(write(client, representation + i, sizeof(char)) < 0) {
            perror("Error at writing number to client.\n");
            exit(0);
        }
    }
}

ZZ Server::receiveNumberFromClient(int client) {
    long numberLength;
    if(read(client, &numberLength, sizeof(long)) < 0) {
        perror ("Error at reading number length from client.\n");
        exit(0);
    }
    unsigned char representation[numberLength + 1];
    for(long i = 0; i < numberLength; ++i) {
        if(read(client, representation + i, sizeof(char)) < 0) {
            perror("Error at writing number to client.\n");
            exit(0);
        }
    }
    ZZ result;
    ZZFromBytes(result, representation, numberLength);
    return result;
}

ZZ Server::decryptMessageUsingCRT(ZZ cryptotext) {

	// We compute c^d mod n by using CRT:
	// First we compute	d mod (p-1), d mod (q - 1) and p ^ (-1) mod q.

	ZZ firstModularExpression = privateKey % (firstPrimeNumber - 1);
	ZZ secondModularExpression = privateKey % (secondPrimeNumber - 1);
	ZZ firstInvModularSecond = InvMod(firstPrimeNumber % secondPrimeNumber, secondPrimeNumber);

	ZZ x1, x2;
	// We compute x1 = (d mod p) ^ n_1  mod p and x2 = (d mod q) ^ n_2 mod q
	x1 = PowerMod(cryptotext % firstPrimeNumber, firstModularExpression, firstPrimeNumber);
	x2 = PowerMod(cryptotext % secondPrimeNumber, secondModularExpression, secondPrimeNumber);

	// The result of c ^ d mod n is: x1 + p((x2 - x1)(p ^ (-1) mod q) mod q).
	ZZ decryptedMessage;
	decryptedMessage = x1 + firstPrimeNumber * (((x2 - x1) * firstInvModularSecond) % secondPrimeNumber);
	return decryptedMessage;
}

void Server::chooseRandomRequests(int* requests, int numberOfRequests) {
	srand(time(NULL));
	for(int i = 0; i < numberOfRequests; ++i) {
		requests[i] = rand() % 2;
	}
}

ZZ Server::findNewInformationAndProduct(RevealedInformation& newInformation, int* requests, int numberOfRequests, int client) {
	newInformation.requests = new int[numberOfRequests];
	newInformation.first = new ZZ[numberOfRequests];
	newInformation.second = new ZZ[numberOfRequests];
	newInformation.third = new ZZ[numberOfRequests];
	ZZ product;
	product = 1;
	for(int i = 0; i < numberOfRequests; ++i) {
		newInformation.first[i] = receiveNumberFromClient(client);
		newInformation.second[i] = receiveNumberFromClient(client);
		newInformation.third[i] = receiveNumberFromClient(client);
		if(requests[i] == 0) {
			ZZ y = GFunction::applyFunction(newInformation.second[i], newInformation.third[i]);
			ZZ res = FFunction::applyFunction(newInformation.first[i], y);
			product = (product * res) % compositeNumber;
		}
		else {
			ZZ x = GFunction::applyFunction(newInformation.first[i], newInformation.second[i]);
			ZZ res = FFunction::applyFunction(x, newInformation.third[i]);
			product = (product * res) % compositeNumber;
		}
	}
	return product;
}


bool Server::verifyCorrectFunction(ZZ blindSignature, ZZ ID, ZZ a, ZZ c, ZZ d, ZZ r) {
    ZZ x = GFunction::applyFunction(a, c);
	ZZ op;
	op = a ^ ID;
	ZZ y = GFunction::applyFunction(op, d);
	ZZ fResult = FFunction::applyFunction(x, y);
	ZZ correctResult = (r * r * r * fResult) % compositeNumber;
	return correctResult == blindSignature;
}

void Server::execute(int client) { // IS it an int??
    sendNumberToClient(compositeNumber, client);
	if(read(client, &securityConstant, sizeof(int)) < 0) {
		perror("Error at reading security constant from client.\n");
		exit(1);
	}
	ZZ encryptedPseudonym = receiveNumberFromClient(client);
	ZZ encryptedResponse = receiveNumberFromClient(client);

	ZZ pseudonym = decryptMessageUsingCRT(encryptedPseudonym);
	ZZ response = decryptMessageUsingCRT(encryptedResponse);
	int numberOfRequests = securityConstant - securityConstant / 2;
	int requests[numberOfRequests];
	chooseRandomRequests(requests, numberOfRequests);
	for(int i = 0; i < numberOfRequests; ++i) {
		if(write(client, requests + i, sizeof(int)) < 0) {
            perror("Error at writing requests to client.\n");
            exit(0);
        }
	}

	RevealedInformation newInformation;
	newInformation.vote = response;
	ZZ product = findNewInformationAndProduct(newInformation, requests, numberOfRequests, client);
	if(pseudonym * pseudonym * pseudonym != product) {
		// it is not constructed correctly
		int response = INVALID;
		if(write(client, &response, sizeof(int)) < 0) {
            perror("Error at writing response to client.\n");
            exit(0);
        }
		return;
	}

	// else, all data is valid. We search for fraud.
	if(impostors.find(pseudonym) != impostors.end()) {
		int responsee = FRAUD;
		ZZ ID = impostors.find(pseudonym)->second;
		if(write(client, &responsee, sizeof(int)) < 0) {
			perror("Error at writing response to client.\n");
			exit(0);
		}
		sendNumberToClient(ID, client);
		storedInformation[pseudonym] = newInformation;
		newInformation.vote == 0 ? ++negativeVotes : ++positiveVotes;
		return;
	}
	// else, he was not revealed yet

	if(storedInformation.find(pseudonym) == storedInformation.end()) {
		int responsee = OK;
		if(write(client, &responsee, sizeof(int)) < 0) {
            perror("Error at writing response to client.\n");
            exit(0);
        }
		return;
	}
	// else, this is the second attempt to vote

	RevealedInformation oldInformation = storedInformation[pseudonym];
	ZZ ID;
	ID = 0;
	for(int i = 0; i < numberOfRequests; ++i) {
		if(oldInformation.requests[i] != newInformation.requests[i]) {
			if(oldInformation.requests[i] == 1) {
				ID = oldInformation.first[i] ^ newInformation.second[i];
			}
			else {
				ID = oldInformation.second[i] ^ newInformation.first[i];
			}
		}
	}

	int responsee = FRAUD;
	if(write(client, &responsee, sizeof(int)) < 0) {
		perror("Error at writing response to client.\n");
		exit(0);
	}
	sendNumberToClient(ID, client);

	impostors[pseudonym] = ID;
	oldInformation.vote == 0 ? --negativeVotes : --positiveVotes;

	return ;
}
