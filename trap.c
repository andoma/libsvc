#include "trap.h"

#if defined(linux) && (defined(__i386__) || defined(__x86_64__))




#define _GNU_SOURCE
#include <link.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <inttypes.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>

#include "strvec.h"
#include "trace.h"
#include "misc.h"

#define MAXFRAMES 100


static char *trap_header;
static char *trap_libs;
static int trap_output_fd;


static void
emit_str(const char *str)
{
  if(write(trap_output_fd, str, strlen(str))) {}
}


static void
emit_hex(uint64_t u64, int bytes)
{
  char str[16];
  if(bytes > 8)
    return;
  emit_str("0x");
  const int nibbles = bytes * 2;
  int x = 0;
  for(int i = nibbles - 1; i >= 0; i--) {
    str[x++] = "0123456789abcdef"[(u64 >> (i * 4)) & 0xf];
  }
  if(write(trap_output_fd, str, nibbles)) {}
}

/**
 *
 */
static void
emit_ptr(void *ptr)
{
  Dl_info dli = {};
  int r = dladdr(ptr, &dli);

  emit_hex((intptr_t)ptr, sizeof(void *));

  if(r && dli.dli_sname != NULL && dli.dli_saddr != NULL) {
    emit_str("  ");
    emit_str(dli.dli_sname);
    emit_str("+");
    emit_hex((intptr_t)(ptr - dli.dli_saddr), sizeof(void *));
    emit_str("  ");
    emit_str(dli.dli_fname);
    return;
  }

  if(dli.dli_fname != NULL) {
    emit_str("  ");
    emit_str(dli.dli_fname);
    return;
  }
}


/**
 *
 */
static void
dumpstack(void *frames[], int nframes)
{
  int i;
  for(i = 0; i < nframes; i++) {
    emit_ptr(frames[i]);
    emit_str("\n");
  }
}


#ifdef __x86_64__


const char regnames[NGREG][8] = {
  [REG_R8  ]=    "r8     ",
  [REG_R9  ]=    "r9     ",
  [REG_R10 ]=    "r10    ",
  [REG_R11 ]=    "r11    ",
  [REG_R12 ]=    "r12    ",
  [REG_R13 ]=    "r13    ",
  [REG_R14 ]=    "r14    ",
  [REG_R15 ]=    "r15    ",
  [REG_RDI ]=    "rdi    ",
  [REG_RSI ]=    "rsi    ",
  [REG_RBP ]=    "rbp    ",
  [REG_RBX ]=    "rbx    ",
  [REG_RDX ]=    "rdx    ",
  [REG_RAX ]=    "rax    ",
  [REG_RCX ]=    "rcx    ",
  [REG_RSP ]=    "rsp    ",
  [REG_RIP ]=    "rip    ",
  [REG_EFL ]=    "efl    ",
  [REG_CSGSFS] = "csgsfs ",
  [REG_ERR] =    "err    ",
  [REG_TRAPNO] = "trapno ",
  [REG_OLDMASK]= "oldmask",
  [REG_CR2] =    "cr2    ",
};
#endif


/**
 *
 */
static void
traphandler(int sig, siginfo_t *si, void *UC)
{
  struct sigaction sa = {
    .sa_handler = SIG_DFL
  };

  sigaction(sig, &sa, NULL);

  if(trap_output_fd == -1)
    return;

  ucontext_t *uc = UC;

  static void *frames[MAXFRAMES];
  int nframes = backtrace(frames, MAXFRAMES);
  const char *reason = NULL;

  char prname[17] = {0};

  // prctl(PR_GET_NAME, prname, 0, 0, 0);

  emit_str("Signal: ");
  emit_hex(sig, 4);
  if(prname[0]) {
    emit_str(" in thread: \"");
    emit_str(prname);
    emit_str("\"");
  }
  emit_str(" in ");
  emit_str(trap_header);
  emit_str("\n");

  switch(sig) {
  case SIGSEGV:
    switch(si->si_code) {
    case SEGV_MAPERR:  reason = "Address not mapped"; break;
    case SEGV_ACCERR:  reason = "Access error"; break;
    }
    break;

  case SIGFPE:
    switch(si->si_code) {
    case FPE_INTDIV:  reason = "Integer division by zero"; break;
    }
    break;
  }

  //  addr2text(buf, sizeof(buf), si->si_addr);

  emit_str("FAULT ADDRESS: ");
  emit_ptr(si->si_addr);
  if(reason != NULL) {
    emit_str("  Reason: ");
    emit_str(reason);
  }
  emit_str("\n==== LOADED LIBRARIES:\n");
  emit_str(trap_libs);

  emit_str("\n==== REGISTER DUMP:\n");
#if defined(__arm__)
  /*
  TRAPMSG("   trap_no = 0x%08lx", uc->uc_mcontext.trap_no);
  TRAPMSG("error_code = 0x%08lx", uc->uc_mcontext.error_code);
  TRAPMSG("   oldmask = 0x%08lx", uc->uc_mcontext.oldmask);
  TRAPMSG("        R0 = 0x%08lx", uc->uc_mcontext.arm_r0);
  TRAPMSG("        R1 = 0x%08lx", uc->uc_mcontext.arm_r1);
  TRAPMSG("        R2 = 0x%08lx", uc->uc_mcontext.arm_r2);
  TRAPMSG("        R3 = 0x%08lx", uc->uc_mcontext.arm_r3);
  TRAPMSG("        R4 = 0x%08lx", uc->uc_mcontext.arm_r4);
  TRAPMSG("        R5 = 0x%08lx", uc->uc_mcontext.arm_r5);
  TRAPMSG("        R6 = 0x%08lx", uc->uc_mcontext.arm_r6);
  TRAPMSG("        R7 = 0x%08lx", uc->uc_mcontext.arm_r7);
  TRAPMSG("        R8 = 0x%08lx", uc->uc_mcontext.arm_r8);
  TRAPMSG("        R9 = 0x%08lx", uc->uc_mcontext.arm_r9);
  TRAPMSG("       R10 = 0x%08lx", uc->uc_mcontext.arm_r10);
  TRAPMSG("        FP = 0x%08lx", uc->uc_mcontext.arm_fp);
  TRAPMSG("        IP = 0x%08lx", uc->uc_mcontext.arm_ip);
  TRAPMSG("        SP = 0x%08lx", uc->uc_mcontext.arm_sp);
  TRAPMSG("        LR = 0x%08lx", uc->uc_mcontext.arm_lr);
  TRAPMSG("        PC = 0x%08lx", uc->uc_mcontext.arm_pc);
  TRAPMSG("      CPSR = 0x%08lx", uc->uc_mcontext.arm_cpsr);
  TRAPMSG("fault_addr = 0x%08lx", uc->uc_mcontext.fault_address);
  */
#else
  int i;
  for(i = 0; i < NGREG; i++) {
    emit_str(regnames[i]);
    emit_str(" = ");
    emit_hex(uc->uc_mcontext.gregs[i], __WORDSIZE / 8);
    emit_str("\n");
  }
#endif

  emit_str("==== STACKTRACE:\n");
  if(0) {
    dumpstack(frames, nframes);
  } else {
    backtrace_symbols_fd(frames, nframes, trap_output_fd);
  }

  close(trap_output_fd);
  trap_output_fd = -1;
}




static int
iterate_libs_callback(struct dl_phdr_info *info, size_t size, void *data)
{
  if(info->dlpi_name[0])
    strvec_push(data, info->dlpi_name);
  return 0;
}


static void (*crashmsgcb)(const char *str);

static void
trap_child(int fd)
{
  prctl(PR_SET_NAME, "traphandler", 0, 0, 0);

  ssize_t trapmsgsize = 65536;
  char *trapmsg = malloc(trapmsgsize + 1);
  ssize_t offset = 0;

  while(offset < trapmsgsize) {
    size_t r = read(fd, trapmsg + offset, trapmsgsize - offset);
    if(r <= 0)
      break;
    offset += r;
  }

  if(offset > 0) {
    trapmsg[offset] = 0;

    if(crashmsgcb != NULL) {
      crashmsgcb(trapmsg);
    } else {
      fprintf(stderr, "%s\n", trapmsg);
    }
  }
  exit(0);
}



/**
 *
 */
void
trap_init(void (*crashmsg)(const char *str), char *argv0)
{
  struct sigaction sa;
  char self[4096];
  char path[256];
  int r;

  crashmsgcb = crashmsg;
  int fds[2];

  if(pipe2(fds, O_CLOEXEC))
    return;

  trap_output_fd = fds[1];

  r = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if(r == -1)
    self[0] = 0;
  else
    self[r] = 0;

  trap_header = fmt("EXE: %s, CWD: %s", self, getcwd(path, sizeof(path)));

  scoped_strvec(libs);
  dl_iterate_phdr(iterate_libs_callback, &libs);
  trap_libs = strvec_join(&libs, " ");

  if(!fork()) {
    if(argv0 != NULL) {
      argv0[0] = '_'; // Change process title
    }
    close(fds[1]);
    trap_child(fds[0]);
  }

  memset(&sa, 0, sizeof(sa));

  sigset_t m;
  sigemptyset(&m);
  sigaddset(&m, SIGSEGV);
  sigaddset(&m, SIGBUS);
  sigaddset(&m, SIGILL);
  sigaddset(&m, SIGABRT);
  sigaddset(&m, SIGFPE);

  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = traphandler;
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS,  &sa, NULL);
  sigaction(SIGILL,  &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGFPE,  &sa, NULL);

  sigprocmask(SIG_UNBLOCK, &m, NULL);
  close(fds[0]);  // Close read end of pipe
}



#else

void
trap_init(void (*crashmsg)(const char *str), char *argv0)
{
}
#endif

