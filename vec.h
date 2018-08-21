#pragma once

#define VEC_HEAD(name, type) struct name {      \
    type *vh_p;                                 \
    size_t vh_length;                           \
    size_t vh_capacity;                         \
  }

#define VEC_ITEM(head, n) (head)->vh_p[n]

#define VEC_LEN(head) ((head)->vh_length)

#define VEC_RESIZE(head, n) do {                                \
    if(n > (head)->vh_capacity) {                               \
      (head)->vh_capacity = (n) * 2;                            \
      size_t memsiz = (head)->vh_capacity *                     \
        sizeof(typeof((head)->vh_p[0]));                        \
      (head)->vh_p = realloc((head)->vh_p, memsiz);             \
    }                                                           \
    (head)->vh_length = n;                                      \
  } while(0)

#define VEC_SET_CAPACITY(head, n) do {                          \
    if(n > (head)->vh_capacity) {                               \
      (head)->vh_capacity = (n);                                \
      size_t memsiz = (head)->vh_capacity *                     \
        sizeof(typeof((head)->vh_p[0]));                        \
      (head)->vh_p = realloc((head)->vh_p, memsiz);             \
    }                                                           \
  } while(0)

#define VEC_PUSH_BACK(head, item) do {          \
    size_t cursize = VEC_LEN(head);             \
    VEC_RESIZE(head, cursize + 1);              \
    VEC_ITEM(head, cursize) = (item);           \
  } while(0)

#define VEC_POP(head) (head)->vh_length--

#define VEC_CLEAR(head) do {                    \
    (head)->vh_capacity = 0;                    \
    (head)->vh_length = 0;                      \
    free((head)->vh_p);                         \
  } while(0)


#define VEC_SORT(head, cmpfun)                                          \
  qsort((head)->vh_p, (head)->vh_length,                                \
        sizeof((head)->vh_p[0]), (void *)cmpfun)
