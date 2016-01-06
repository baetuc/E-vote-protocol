#pragma once
#include <NTL/ZZ.h>
#include <fstream>
#include <string>
#include <set>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <iostream>
#include "FFunction.h"
#include "GFunction.h"

#define PRIMES_LENGTH 15
#define VALID_IDS "ids.txt"
#define INFORMATION "serverInfo.txt"
#define SECURITY_CONSTANT 10

#define ID_OK 0
#define ID_INVALID 1
#define ID_USED 2

#define OK 0
#define NOT_OK 1

using namespace std;
using namespace NTL;

ZZ compositeNumber, firstPrimeNumber, secondPrimeNumber;
ZZ phiCompositeNumber;
ZZ privateKey;
int securityConstant;
std::set<ZZ> validIds;
std::set<ZZ> usedIDs;

class Server {
private:
	static void generatePrimes();
	static void computeCompositeAndPhi();
	static void computePrivateKey();
    static void initializeValidIDs();
    static void sendNumberToClient(ZZ& number, int client);
	static ZZ receiveNumberFromClient(int client);
    static ZZ signBlindMessageUsingCRT(ZZ blindMessage); // sign a single blinded message
    static void chooseRandomIndexes(bool*);
	static void receiveBlindSignaturesFromClient(int client, vector<ZZ>& blindSignatures);
	static void receiveParametersForChecking(int client, ZZ* a, ZZ* c, ZZ* d, ZZ* r);
	static bool verifyCorrectFunction(ZZ blindSignature, ZZ ID, ZZ a, ZZ c, ZZ d, ZZ r);

public:
	static void initialize();
    static void execute(int client);
};

void Server::generatePrimes() {
	firstPrimeNumber = GenPrime_ZZ(PRIMES_LENGTH);
	while ((firstPrimeNumber - 1) % 3 == 0) {
		firstPrimeNumber = GenPrime_ZZ(PRIMES_LENGTH);
	}
	secondPrimeNumber = GenPrime_ZZ(PRIMES_LENGTH);
	while (secondPrimeNumber == firstPrimeNumber || (secondPrimeNumber - 1) % 3 == 0) {
		secondPrimeNumber = GenPrime_ZZ(PRIMES_LENGTH);
	}
}

 void Server::computeCompositeAndPhi() {
	compositeNumber = firstPrimeNumber * secondPrimeNumber;
	phiCompositeNumber = (firstPrimeNumber - 1) * (secondPrimeNumber - 1);
}

void Server::computePrivateKey() {
	ZZ publicKey;
	publicKey = 3;
	privateKey = InvMod(publicKey, phiCompositeNumber);
}

void Server::initializeValidIDs() {
    ifstream in(VALID_IDS);
    int numberOfIDs;
    in >> numberOfIDs;
    ZZ id;
    for(int i = 0; i < numberOfIDs; ++i) {
        in >> id;
        validIds.insert(id);
    }
    in.close();
}

void Server::initialize() {
	generatePrimes();
	computeCompositeAndPhi();
	computePrivateKey();
    initializeValidIDs();
    securityConstant = SECURITY_CONSTANT;
	ofstream out(INFORMATION, fstream::trunc | fstream::out);
	out << privateKey << '\n' << compositeNumber << '\n' << firstPrimeNumber << '\n' << secondPrimeNumber << '\n';
	out.close();

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

ZZ Server::signBlindMessageUsingCRT(ZZ blindMessage) {

	// We compute c^d mod n by using CRT:
	// First we compute	d mod (p-1), d mod (q - 1) and p ^ (-1) mod q.

	ZZ firstModularExpression = privateKey % (firstPrimeNumber - 1);
	ZZ secondModularExpression = privateKey % (secondPrimeNumber - 1);
	ZZ firstInvModularSecond = InvMod(firstPrimeNumber % secondPrimeNumber, secondPrimeNumber);

	ZZ x1, x2;
	// We compute x1 = (d mod p) ^ n_1  mod p and x2 = (d mod q) ^ n_2 mod q
	x1 = PowerMod(blindMessage % firstPrimeNumber, firstModularExpression, firstPrimeNumber);
	x2 = PowerMod(blindMessage % secondPrimeNumber, secondModularExpression, secondPrimeNumber);

	// The result of c ^ d mod n is: x1 + p((x2 - x1)(p ^ (-1) mod q) mod q).
	ZZ signedBlindMessage;
	signedBlindMessage = x1 + firstPrimeNumber * (((x2 - x1) * firstInvModularSecond) % secondPrimeNumber);
	return signedBlindMessage;
}


void Server::chooseRandomIndexes(bool* chosenIndex) {
    int numberOfChosenIndexes = 0;
    for(int i = 0; i < SECURITY_CONSTANT; ++i) {
        chosenIndex[i] = false;
    }
    while(numberOfChosenIndexes < SECURITY_CONSTANT / 2) {
        long index = RandomBnd(SECURITY_CONSTANT);
        if(!chosenIndex[index]) {
            chosenIndex[index] = true;
            ++numberOfChosenIndexes;
        }
    }
}


void Server::receiveBlindSignaturesFromClient(int client, vector<ZZ>& blindSignatures) {
    for(int i = 0; i < securityConstant; ++i) {
		ZZ blindSignature = receiveNumberFromClient(client);
        blindSignatures.push_back(blindSignature);
    }
}
void Server::receiveParametersForChecking(int client, ZZ* a, ZZ* c, ZZ* d, ZZ* r) {
    for(int i = 0; i < securityConstant / 2; ++i) {
        // fill the information
        a[i] = receiveNumberFromClient(client);
        c[i] = receiveNumberFromClient(client);
        d[i] = receiveNumberFromClient(client);
        r[i] = receiveNumberFromClient(client);
    }
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
    // we have the server initialized, first send the crypto parameters to client
    sendNumberToClient(compositeNumber, client);
    if(write(client, &securityConstant, sizeof(int)) < 0) {
        perror ("Error at writing security constant to client.\n");
        exit(0);
    }

	ZZ clientID;
	clientID = receiveNumberFromClient(client); // we must know the client's ID
	int response;
	if(validIds.find(clientID) == validIds.end()) {
		// ID isn't valid
		response = ID_INVALID;
		if (write(client, &response, sizeof(int)) < 0) {
			perror ("Error at writing response to client.\n");
			exit(0);
		}
		return;
	}
	if(usedIDs.find(clientID) != usedIDs.end()) {
		// ID isn't valid
		response = ID_USED;
		if (write(client, &response, sizeof(int)) < 0) {
			perror ("Error at writing response to client.\n");
			exit(0);
		}
		return;
	}
	response = ID_OK;
	usedIDs.insert(clientID);
	if (write(client, &response, sizeof(int)) < 0) {
		perror("Error at writing response to client.\n");
		exit(0);
	}

    vector<ZZ> blindSignatures;
    receiveBlindSignaturesFromClient(client, blindSignatures);
    bool chosenIndexes[securityConstant];
    chooseRandomIndexes(chosenIndexes);

    for(int i = 0; i < securityConstant; ++i) {
        if(chosenIndexes[i]) {
            if(write(client, &i, sizeof(int)) < 0) {
                perror("Error at writing chosen indexes to client.\n");
                exit(0);
            }
        }
    }
    // The server transmitted chosen indexes, now has to receive from the client the information

    ZZ a[securityConstant / 2], c[securityConstant / 2], d[securityConstant / 2], r[securityConstant / 2];
    receiveParametersForChecking(client, a, c, d, r);
    int foundIndexes = 0;
	bool allFine = true;
	// allFine becomes false when there is a function's result which is faulty computed.
    for(int i = 0; i < securityConstant && allFine; ++i) {
        if(chosenIndexes[i]) {
			allFine = verifyCorrectFunction(blindSignatures[i], clientID, a[foundIndexes],
				c[foundIndexes], d[foundIndexes], r[foundIndexes]);
            ++foundIndexes;
        }
    }
	if(allFine) {
		int feedBack = OK;
		if(write(client, &feedBack, sizeof(int)) < 0) {
			perror("Error at writing feedBack to client.\n");
			exit(0);
		}
		ZZ product;
		product = 1;
		for(int i = 0; i < securityConstant; ++i) {
			if(!chosenIndexes[i]) { // if no information was found from these
				product *= signBlindMessageUsingCRT(blindSignatures[i]);
				product = product % compositeNumber;
			}
		}
		sendNumberToClient(product, client);
	}
	else {
		int feedBack = NOT_OK;
		if(write(client, &feedBack, sizeof(int)) < 0) {
			perror("Error at writing feedBack to client.\n");
			exit(0);
		}
	}
}
