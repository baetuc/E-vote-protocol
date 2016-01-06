#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

class GFunction {

public:
    static ZZ applyFunction(ZZ& firstParameter, ZZ& secondParameter);
};

ZZ GFunction::applyFunction(ZZ& firstParameter, ZZ& secondParameter) {
    ZZ result;
    result = 1;

    return result;
}
