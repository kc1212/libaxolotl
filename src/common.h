
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

// positive because to distinguish between libsodium (it returns -1)
enum AXOLOTL_RETURN_CODES {
	AXOLOTL_SUCCESS = 0,
	AXOLOTL_INVALID_KEY,
	AXOLOTL_INVALID_KEYLEN,
	AXOLOTL_NULL_POINTER,
	AXOLOTL_CRITICAL_ERROR,
	AXOLOTL_TOTAL
};

