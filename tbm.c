#include <stdio.h>
#include <sys/param.h>

#include "tbm.h"
#include "misc.h"

/**
 *
 */
uint64_t
tbm_withdraw(token_bucket_meter_t *tb, double amount)
{
  if(tb->tokens < amount) {
    uint64_t now = get_ts_mono();
    const uint64_t delta = now - tb->last_fill;
    const double add = tb->rate * delta / 1000000.0;
    tb->tokens = MIN(tb->tokens + add, tb->burst);
    tb->last_fill = now;

    if(tb->tokens < amount) {
      return 1 + amount * 1e6 / tb->rate;
    }
  }
  tb->tokens -= amount;
  return 0;
}


void
tbm_init(token_bucket_meter_t *tb, double rate, double burst)
{
  tb->last_fill = get_ts_mono();
  tb->tokens = burst;
  tb->burst = burst;
  tb->rate = rate;
}
