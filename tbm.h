#pragma once

#include <stdint.h>


typedef struct token_bucket_meter {
  uint64_t last_fill;
  double tokens;
  double burst;
  double rate;
} token_bucket_meter_t;


// Returns 0 if granted, otherwise returns time in ms until first possible grant
uint64_t tbm_withdraw(token_bucket_meter_t *tb, double amount);

void tbm_init(token_bucket_meter_t *tb, double rate, double burst);
