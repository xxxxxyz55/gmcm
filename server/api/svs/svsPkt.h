#ifndef _GMCM_SVS_PKT_H_
#define _GMCM_SVS_PKT_H_
#include "../../encode/json/j2c.h"

JSON_SEQ_REF(reqNULL)
JSON_SEQ_END_REF(reqNULL)

JSON_SEQ_REF(reqGenerateRandom)
JSON_FIELD(length, jDouble, 1, NULL)
JSON_SEQ_END_REF(reqGenerateRandom)


JSON_SEQ_REF(reqSvsGenKey)
JSON_FIELD(type, jString, 1, NULL)
JSON_FIELD(bits, jDouble, 0, NULL)
JSON_SEQ_END_REF(reqSvsGenKey)

JSON_SEQ_REF(reqSvsGenCsr)
JSON_FIELD(prikey, jString, 1, NULL)
JSON_FIELD(subj, jString, 1, NULL)
JSON_SEQ_END_REF(reqSvsGenCsr)

JSON_SEQ_REF(reqSvsSignCert)
JSON_FIELD(csr, jString, 1, NULL)
JSON_FIELD(caCert, jString, 0, NULL)
JSON_FIELD(caKey, jString, 1, NULL)
JSON_FIELD(usage, jString, 1, NULL)
JSON_SEQ_END_REF(reqSvsSignCert)

#endif