#pragma once

char *azure_sas_token(const char *resource, const char *sakey,
                      int valid_duration, const char *keyname);
