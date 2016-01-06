#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

class GFunction {

public:
    static ZZ applyFunction(ZZ& firstParameter, ZZ& secondParameter, ZZ g, ZZ compositeNumber);
};

ZZ GFunction::applyFunction(ZZ& firstParameter, ZZ& secondParameter, ZZ g, ZZ compositeNumber) {
    ZZ result = PowerMod(firstParameter, g, compositeNumber);
    result += PowerMod(secondParameter, g, compositeNumber);
    result = result % compositeNumber;
}
