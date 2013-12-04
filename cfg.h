#include "libsvc/htsmsg.h"

typedef htsmsg_t cfg_t;

int cfg_load(const char *filename, const char *defconf);

cfg_t *cfg_get_root(void);

void cfg_releasep(cfg_t **p);

#define cfg_root(x) cfg_t *x __attribute__((cleanup(cfg_releasep))) = cfg_get_root();

#define CFG(name...) (const char *[]){name, NULL}
#define CFGI(x) (const char *[]){HTSMSG_INDEX(x), NULL}
#define CFG_INDEX(x) HTSMSG_INDEX(x)

const char *cfg_get_str(cfg_t *c, const char **vec, const char *def);

int64_t cfg_get_s64(cfg_t *c, const char **path, int64_t def);

int cfg_get_int(cfg_t *c, const char **path, int def);

cfg_t *cfg_get_map(cfg_t *c, const char *id);

cfg_t *cfg_get_list(cfg_t *c, const char *id);

int cfg_list_length(cfg_t *c);
