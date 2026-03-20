#pragma once

char *azure_sas_token(const char *resource, const char *sakey,
                      int valid_duration, const char *keyname);

// Read a cached access token from the Azure CLI MSAL token cache.
// Returns a heap-allocated "Bearer <token>" string, or NULL if no valid
// (non-expired) cached token is found for the given resource.
char *azure_cli_get_token(const char *resource);

struct ntv *azure_vm_get_machine_identity(void);

struct ntv *azure_vm_get_machine_token(const char *aud);
