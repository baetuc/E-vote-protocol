#include <NTL/ZZ.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include "FFunction.h"
#include "GFunction.h"

#define INFORMATION "../OfficeClient/votingInformation"
#define OK 0
#define INVALID 1

using namespace std;
using namespace NTL;

ZZ ID;
ZZ pseudonym;
int securityConstant;
ZZ *a, *c, *d, *r;
ZZ publicKey;
ZZ compositeNumber;

class Client {
private:
    static ZZ receiveNumberFromServer(int sd);
    static void sendNumberToServer(ZZ& number, int sd);
    static string zToString(const ZZ &z);
    static ZZ cstringToNumber(char x[]);
    static void initializeFromFile(ZZ ID);
    static void revealSubsecrets(int sd, int* requests, ZZ* a, ZZ* c, ZZ* d, ZZ* r);

public:
    static void execute(int sd);
};


void Client::sendNumberToServer(ZZ& number, int sd) {
    long numberLength = NumBytes(number);
    if(write(sd, &numberLength, sizeof(long)) < 0) {
        perror("Error at writing number length to server.\n");
        exit(0);
    }
    unsigned char representation[numberLength + 1];
    BytesFromZZ(representation, number, numberLength);
    for(long i = 0; i < numberLength; ++i) {
        if(write(sd, representation + i, sizeof(char)) < 0) {
            perror("Error at writing number to server.\n");
            exit(0);
        }
    }
}

ZZ Client::receiveNumberFromServer(int sd) {
    long numberLength;
    if(read(sd, &numberLength, sizeof(long)) < 0) {
        perror ("Error at reading number length from server.\n");
        exit(0);
    }
    unsigned char representation[numberLength + 1];
    for(long i = 0; i < numberLength; ++i) {
        if(read(sd, representation + i, sizeof(char)) < 0) {
            perror("Error at writing number to server.\n");
            exit(0);
        }
    }
    ZZ result;
    ZZFromBytes(result, representation, numberLength);
    return result;
}

string Client::zToString(const ZZ &z) {
    stringstream buffer;
    buffer << z;
    return buffer.str();
}

ZZ Client::cstringToNumber(char x[]) {
    string s = x;
    istringstream iss(s);
    ZZ z;
    iss >> z;
    return z;
}

void Client::initializeFromFile(ZZ ID) {
    string path;
    path += INFORMATION;
    path += zToString(ID);
    path += ".txt";
    ifstream in(path.c_str());

    in >> pseudonym;
    in >> securityConstant;

    a = new ZZ[securityConstant];
    c = new ZZ[securityConstant];
    d = new ZZ[securityConstant];
    r = new ZZ[securityConstant];

    for(int i = 0; i < securityConstant; ++i) {
        in >> a[i] >> c[i] >> d[i] >> r[i];
    }

    in.close();
}

void Client::revealSubsecrets(int sd, int* requests, ZZ* a, ZZ* c, ZZ* d, ZZ* r) {
    for(int i = 0; i < (securityConstant - securityConstant / 2); ++i) {
        if(requests[i] == 0) {
            ZZ x = GFunction::applyFunction(a[i], c[i]);
            ZZ secondPart = a[i] ^ ID;
            sendNumberToServer(x, sd);
            sendNumberToServer(secondPart, sd);
            sendNumberToServer(d[i], sd);
        }
        else {
            ZZ part = a[i] ^ ID;
            ZZ y = GFunction::applyFunction(part, d[i]);
            sendNumberToServer(a[i], sd);
            sendNumberToServer(c[i], sd);
            sendNumberToServer(y, sd);
        }
    }
}

void Client::execute(int sd) {
    cout << "Please insert a valid ID: ";
    ZZ ID;
    cin >> ID;
    initializeFromFile(ID);
    cout << "Question: Do you want the linden trees to be replanted on Stefan cel Mare Boulevard?\n";
    cout << "Vote with 0 for NO and 1 for YES: ";
    ZZ response;
    cin >> response;

    // We now start the communication with the Server
    compositeNumber = receiveNumberFromServer(sd);
    publicKey = 3;

    if(write(sd, &securityConstant, sizeof(int)) < 0) {
        perror("Error at writing security constant to server.\n");
        exit(1);
    }

    // We encrypt the messages
    ZZ encryptedPseudonym = PowerMod(pseudonym, publicKey, compositeNumber);
    ZZ encryptedResponse = PowerMod(response, publicKey, compositeNumber);

    sendNumberToServer(encryptedPseudonym, sd);
    sendNumberToServer(encryptedResponse, sd);

    // The first k - k / 2 indexes are the ones that we look for

    int numberOfRequests = securityConstant - securityConstant / 2;
    int requests[numberOfRequests];
    for(int i = 0; i < numberOfRequests; ++i) {
        if(read(sd, requests + i, sizeof(int)) < 0) {
            perror("Error at reading requests from server.\n");
            exit(0);
        }
    }
    revealSubsecrets(sd, requests, a, c, d, r);

    int finalResponse;
    if(read(sd, &finalResponse, sizeof(int)) < 0) {
        perror("Error at reading final response from server.\n");
        exit(0);
    }

    if(finalResponse == OK) {
        cout << "Thank your for your response!\n";
    }
    else {
        if(finalResponse == INVALID) {
            std::cout << "You entered invalid data!" << std::endl;
        }
        else {
            ZZ foundID = receiveNumberFromServer(sd);
            cout << "You are a fraud! Your ID is " << foundID << " and you will support consequences.\n";
        }
    }
}
