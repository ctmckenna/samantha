#ifndef _SAMMY_CONTEXT__H_
#define _SAMMY_CONTEXT__H_

#include "ribs.h"

struct sammy_context {
    struct hashtable query_params;
};

void sammy_context_init();
const char *sammy_context_get_query_param(const char *param);

#endif //_SAMMY_CONTEXT__H_
