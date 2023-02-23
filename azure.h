#pragma once

char *azure_sas_token(const char *resource, const char *sakey,
                      int valid_duration, const char *keyname);

struct ntv *azure_vm_get_machine_identity(void);

struct ntv *azure_vm_get_machine_token(const char *aud);
