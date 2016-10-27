/******************************************************************************
* Copyright (C) 2013 - 2014 Andreas Öman
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

#define _ISOC99_SOURCE

#include <math.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "dbl.h"


double
my_str2double(const char *str, const char **endp)
{
  double ret = 1.0f;
  int n = 0, m = 0, e = 0;
  unsigned long long o = 0;

  while(*str && *str < 33)
    str++;

  if(*str == '-') {
    ret = -1.0f;
    str++;
  }

  while(*str >= '0' && *str <= '9')
    n = n * 10 + *str++ - '0';

  if(*str != '.') {
    ret *= n;
  } else {

    str++;

    while(*str >= '0' && *str <= '9') {
      if(m > -16) {
        o = o * 10 + *str - '0';
        m--;
      }
      str++;
    }

    ret *= (n + pow(10, m) * o);
  }

  if(*str == 'e' || *str == 'E') {
    int esign = 1;
    str++;
    
    if(*str == '+')
      str++;
    else if(*str == '-') {
      str++;
      esign = -1;
    }
    
    while(*str >= '0' && *str <= '9')
      e = e * 10 + *str++ - '0';
    ret *= pow(10, e * esign);
  }

  if(endp != NULL)
    *endp = str;

  return ret;
}




/*
** The code that follow is based on "printf" code that dates from the
** 1980s. It is in the public domain.  The original comments are
** included here for completeness.  They are very out-of-date but
** might be useful as an historical reference.
**
**************************************************************************
**
** The following modules is an enhanced replacement for the "printf" subroutines
** found in the standard C library.  The following enhancements are
** supported:
**
**      +  Additional functions.  The standard set of "printf" functions
**         includes printf, fprintf, sprintf, vprintf, vfprintf, and
**         vsprintf.  This module adds the following:
**
**           *  snprintf -- Works like sprintf, but has an extra argument
**                          which is the size of the buffer written to.
**
**           *  mprintf --  Similar to sprintf.  Writes output to memory
**                          obtained from malloc.
**
**           *  xprintf --  Calls a function to dispose of output.
**
**           *  nprintf --  No output, but returns the number of characters
**                          that would have been output by printf.
**
**           *  A v- version (ex: vsnprintf) of every function is also
**              supplied.
**
**      +  A few extensions to the formatting notation are supported:
**
**           *  The "=" flag (similar to "-") causes the output to be
**              be centered in the appropriately sized field.
**
**           *  The %b field outputs an integer in binary notation.
**
**           *  The %c field now accepts a precision.  The character output
**              is repeated by the number of times the precision specifies.
**
**           *  The %' field works like %c, but takes as its character the
**              next character of the format string, instead of the next
**              argument.  For example,  printf("%.78'-")  prints 78 minus
**              signs, the same as  printf("%.78c",'-').
**
**      +  When compiled using GCC on a SPARC, this version of printf is
**         faster than the library printf for SUN OS 4.1.
**
**      +  All functions are fully reentrant.
**
*/


static char
getdigit(double *val, int *cnt)
{
  int digit;
  double d;
  if( (*cnt)++ >= 16 ) return '0';
  digit = (int)*val;
  d = digit;
  digit += '0';
  *val = (*val - d)*10.0;
  return (char)digit;
}

#define xGENERIC 0
#define xFLOAT 1
#define xEXP 2


int
my_double2str(char *buf, size_t bufsize, double realvalue)
{
  int precision = -1;
  char *bufpt;
  char prefix;
  char xtype = xGENERIC;
  int idx, exp, e2;
  double rounder;
  char flag_exp;
  char flag_rtz;
  char flag_dp;
  char flag_alternateform = 0;
  char flag_altform2 = 0;
  int nsd;

  if(bufsize < 8)
    return -1;

  if( precision<0 ) precision = 20;         /* Set default precision */
  if( precision>bufsize/2-10 ) precision = bufsize/2-10;
  if( realvalue<0.0 ){
    realvalue = -realvalue;
    prefix = '-';
  }else{
    prefix = 0;
  }
  if( xtype==xGENERIC && precision>0 ) precision--;
  for(idx=precision, rounder=0.5; idx>0; idx--, rounder*=0.1){}

  if( xtype==xFLOAT ) realvalue += rounder;
  /* Normalize realvalue to within 10.0 > realvalue >= 1.0 */
  exp = 0;

  if(isnan(realvalue)) {
    strcpy(buf, "NaN");
    return 0;
  }

  if( realvalue>0.0 ){
    while( realvalue>=1e32 && exp<=350 ){ realvalue *= 1e-32; exp+=32; }
    while( realvalue>=1e8 && exp<=350 ){ realvalue *= 1e-8; exp+=8; }
    while( realvalue>=10.0 && exp<=350 ){ realvalue *= 0.1; exp++; }
    while( realvalue<1e-8 ){ realvalue *= 1e8; exp-=8; }
    while( realvalue<1.0 ){ realvalue *= 10.0; exp--; }
    if( exp>350 ){
      if( prefix=='-' ){
	strcpy(buf, "-Inf");
      }else{
	strcpy(buf, "Inf");
      }
      return 0;
    }
  }
  bufpt = buf;

  /*
  ** If the field type is etGENERIC, then convert to either etEXP
  ** or etFLOAT, as appropriate.
  */
  flag_exp = xtype==xEXP;
  if( xtype != xFLOAT ){
    realvalue += rounder;
    if( realvalue>=10.0 ){ realvalue *= 0.1; exp++; }
  }
  if( xtype==xGENERIC ){
    flag_rtz = !flag_alternateform;
    if( exp<-4 || exp>precision ){
      xtype = xEXP;
    }else{
      precision = precision - exp;
      xtype = xFLOAT;
    }
  }else{
    flag_rtz = 0;
  }
  if( xtype==xEXP ){
    e2 = 0;
  }else{
    e2 = exp;
  }
  nsd = 0;
  flag_dp = (precision>0 ?1:0) | flag_alternateform | flag_altform2;
  /* The sign in front of the number */
  if( prefix ){
    *(bufpt++) = prefix;
  }
  /* Digits prior to the decimal point */
  if( e2<0 ){
    *(bufpt++) = '0';
  }else{
    for(; e2>=0; e2--){
      *(bufpt++) = getdigit(&realvalue,&nsd);
    }
  }
  /* The decimal point */
  if( flag_dp ){
    *(bufpt++) = '.';
  }
  /* "0" digits after the decimal point but before the first
  ** significant digit of the number */
  for(e2++; e2<0; precision--, e2++){
    assert( precision>0 );
    *(bufpt++) = '0';
  }
  /* Significant digits after the decimal point */
  while( (precision--)>0 ){
    *(bufpt++) = getdigit(&realvalue,&nsd);
  }

  /* Remove trailing zeros and the "." if no digits follow the "." */
  if( flag_rtz && flag_dp ){
    while( bufpt[-1]=='0' ) *(--bufpt) = 0;
    assert( bufpt>buf );
    if( bufpt[-1]=='.' ){
      if( flag_altform2 ){
	*(bufpt++) = '0';
      }else{
	*(--bufpt) = 0;
      }
    }
  }
  /* Add the "eNNN" suffix */
  if( flag_exp || xtype==xEXP ){
    *(bufpt++) = 'e';
    if( exp<0 ){
      *(bufpt++) = '-'; exp = -exp;
    }else{
      *(bufpt++) = '+';
    }
    if( exp>=100 ){
      *(bufpt++) = (char)((exp/100)+'0');        /* 100's digit */
      exp %= 100;
    }
    *(bufpt++) = (char)(exp/10+'0');             /* 10's digit */
    *(bufpt++) = (char)(exp%10+'0');             /* 1's digit */
  }
  *bufpt = 0;
  return 0;
}

