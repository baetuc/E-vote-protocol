#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

class FFunction {

public:
    static ZZ applyFunction(ZZ& firstParameter, ZZ& secondParameter);
};

ZZ FFunction::applyFunction(ZZ& firstParameter, ZZ& secondParameter) {
    ZZ result;
    result = 1;

    return result;
}
