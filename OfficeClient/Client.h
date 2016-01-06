#include <NTL/ZZ.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include "FFunction.h"
#include "GFunction.h"

using namespace std;
using namespace NTL;

#define INFORMATION "votingInformation"

#define ID_OK 0
#define ID_INVALID 1
#define ID_USED 2

#define NOT_OK 1

ZZ compositeNumber;
int securityConstant;
vector<ZZ> blindSignatures;

class Client {
private:
    static ZZ receiveNumberFromServer(int sd);
    static void sendNumberToServer(ZZ& number, int sd);
    static string zToString(const ZZ &z);
    static ZZ cstringToNumber(char x[]);
    static void writePseudonymToFile(const char* info, ZZ ID, ZZ pseudonym, ZZ* a, ZZ* c, ZZ* d, ZZ* r, bool*);
    static void sendParametersToServer(int sd, bool* chosenIndexes, ZZ* a, ZZ* c, ZZ* d, ZZ* r);
    static void sendBlindSignaturesToServer(int sd);
    static void createBlindSignatures(ZZ ID, ZZ* a, ZZ* c, ZZ* d, ZZ* r);
    static void generateRandomParameters(ZZ* a, ZZ* c, ZZ* d, ZZ* r);

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


void Client::generateRandomParameters(ZZ* a, ZZ* c, ZZ* d, ZZ* r) {
    for (int i = 0; i < securityConstant; ++i) {
        a[i] = RandomBnd(compositeNumber);
        c[i] = RandomBnd(compositeNumber);
        d[i] = RandomBnd(compositeNumber);
        r[i] = RandomBnd(compositeNumber);
    }
}

void Client::createBlindSignatures(ZZ ID, ZZ* a, ZZ* c, ZZ* d, ZZ* r) {
    for(int i = 0; i < securityConstant; ++i) {
        ZZ x = GFunction::applyFunction(a[i], c[i]);
    	ZZ op;
    	op = a[i] ^ ID;
    	ZZ y = GFunction::applyFunction(op, d[i]);
    	ZZ fResult = FFunction::applyFunction(x, y);
    	blindSignatures.push_back((r[i] * r[i] * r[i] * fResult) % compositeNumber);
    }
}

void Client::sendBlindSignaturesToServer(int sd) {
    for(int i = 0; i < securityConstant; ++i) {
        sendNumberToServer(blindSignatures[i], sd);
    }
}

void Client::sendParametersToServer(int sd, bool* chosenIndexes, ZZ* a, ZZ* c, ZZ* d, ZZ* r) {
    for(int i = 0; i < securityConstant; ++i) {
        if(chosenIndexes[i]) {
            sendNumberToServer(a[i], sd);
            sendNumberToServer(c[i], sd);
            sendNumberToServer(d[i], sd);
            sendNumberToServer(r[i], sd);
        }
    }
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

void Client::writePseudonymToFile(const char* info, ZZ ID, ZZ pseudonym, ZZ* a, ZZ* c, ZZ* d, ZZ* r, bool* chosen) {
    string path;
    path += info;
    path += zToString(ID);
    path += ".txt";
    ofstream out(path.c_str(), fstream::trunc | fstream::out);

    out << pseudonym << '\n';
    out << securityConstant << '\n';
    for(int i = 0; i < securityConstant; ++i) {
        if(!chosen[i]) {
            out << a[i] << '\n' << c[i] << '\n' << d[i] << '\n' << r[i] << '\n';
        }
    }
    for(int i = 0; i < securityConstant; ++i) {
        if(chosen[i]) {
            out << a[i] << '\n' << c[i] << '\n' << d[i] << '\n' << r[i] << '\n';
        }
    }

    out.close();
}

void Client::execute(int sd) {
    compositeNumber = receiveNumberFromServer(sd);
    if(read(sd, &securityConstant, sizeof(int)) < 0) {
        perror ("Error at reading security constant from server.\n");
        exit(0);
    }

    cout << "Please insert a valid ID: ";
    ZZ ID;
    cin >> ID;
    sendNumberToServer(ID, sd);
    int response;
    if (read(sd, &response, sizeof(int)) < 0) {
        perror ("Error at reading response from server.\n");
        exit(0);
    }

    if(response == ID_INVALID) {
        cout << "Invalid ID. Please don't try to cheat!\n";
        return;
    }
    if(response == ID_USED) {
        cout << "You already used this ID. Please be fair!\n";
        return;
    }
    // else is ID_OK

    ZZ* a = new ZZ[securityConstant];
    ZZ* c = new ZZ[securityConstant];
    ZZ* d = new ZZ[securityConstant];
    ZZ* r = new ZZ[securityConstant];

    generateRandomParameters(a, c, d, r);
    createBlindSignatures(ID, a, c, d, r);
    for(int i = 0; i < securityConstant; ++i) {
    }
    sendBlindSignaturesToServer(sd);

    bool* chosenIndexes = new bool[securityConstant];
    for(int i = 0; i < securityConstant; ++i) {
        chosenIndexes[i] = false;
    }
    for(int i = 0; i < securityConstant / 2; ++i) {
        int index;
        if(read(sd, &index, sizeof(int)) < 0) {
            perror("Error at reading chosen index from server.\n");
            exit(0);
        }
        chosenIndexes[index] = true;
    }
    sendParametersToServer(sd, chosenIndexes, a, c, d, r);
    int feedBack;
    if(read(sd, &feedBack, sizeof(int)) < 0) {
        perror("Error at reading feedBack from server.\n");
        exit(0);
    }
    if(feedBack == NOT_OK) {
        cout << "You are trying to cheat! We caught you!\n";
        return;
    }
    // else, the response is OKEY
    ZZ noisedPseudonym;
    noisedPseudonym = receiveNumberFromServer(sd);
    ZZ noise;
    noise = 1;
    for(int i = 0; i < securityConstant; ++i) {
        if(!chosenIndexes[i]) {
            noise = (noise * r[i]) % compositeNumber;
        }
    }
    ZZ pseudonym = noisedPseudonym / noise;
    writePseudonymToFile(INFORMATION, ID, pseudonym, a, c, d, r, chosenIndexes);
    cout << "Thank you. Your pseudonym is: " << pseudonym << '\n';
}
