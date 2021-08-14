// includes libsecp with preallocated rangeproof functions
#include "secp256k1.c"
#ifdef ENABLE_MODULE_RANGEPROOF
#ifdef ENABLE_MODULE_RANGEPROOF_PREALLOCATED
#include "rangeproof_preallocated/rangeproof_preallocated_impl.h"
#endif
#endif