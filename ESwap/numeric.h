#ifndef NUMERIC_H
#define NUMERIC_H
#include "emp-tool/emp-tool.h"

namespace emp {

const static int PROVER = 1;
const static int VERIFIER = 2;

#define MOD ((1LL<<61)-1)
#define HALFMOD (MOD>>1)
#define LOGMOD 60

#ifndef BITLENGTH

#define BITLENGTH 55

#endif
const block P=_mm_set_epi64x(MOD,MOD);

void printBlock(block var)  {
    unsigned char *v64val = (unsigned char*) &var;
    for(int i=0;i<16;i++)
        printf("%.2X", v64val[i]);
    puts("");
}

inline void modBlock(block &x) {
    x=_mm_add_epi64(_mm_and_si128(x,P),_mm_srli_epi64(x,61));
    x=_mm_sub_epi64(x,_mm_andnot_si128(_mm_cmpgt_epi64(P,x),P));
}

inline void modBlock_one(block &x) {
    x=_mm_sub_epi64(x,_mm_andnot_si128(_mm_cmpgt_epi64(P,x),P));
}

inline block addBlocks(const block &x,const block &y) {
    block res=_mm_add_epi64(x,y);
    modBlock_one(res);
    return res;
}

inline block subBlocks(const block &x,const block &y) {
    block res=_mm_sub_epi64(P,y);
    return addBlocks(x,res);
}

inline block addCBlocks(const block &x,long long y) {
    return addBlocks(x,_mm_set_epi64x(y,y));
}

long long get_val(const block &val) {
    long long *vv=(long long*)&val;
    return *vv;
}

}
#endif
