#include "trap.h"

#if defined(linux) && (defined(__i386__) || defined(__x86_64__))




#define _GNU_SOURCE
#include <link.h>
#include <unistd.h>
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

#include "trace.h"

#define MAXFRAMES 100


static char trap_line[1024];
static char libs[4096];



#define TRAPMSG(fmt, ...) trace(LOG_ALERT, fmt, ##__VA_ARGS__)


/**
 *
 */
static void
addr2text(char *out, size_t outlen, void *ptr)
{
  Dl_info dli = {};
  //  char buf[256];
  int r = dladdr(ptr, &dli);
  
  if(r && dli.dli_sname != NULL && dli.dli_saddr != NULL) {
    snprintf(out, outlen, "0x%016" PRIxPTR "  %s+0x%tx  (%s)",
	     (intptr_t)ptr, dli.dli_sname, ptr - dli.dli_saddr, dli.dli_fname);
    return;
  }
  /*
  if(self[0] && !add2lineresolve(self, ptr, buf, sizeof(buf))) {
    snprintf(out, outlen, "%s %p", buf, ptr);
    return;
  }
  */
  if(dli.dli_fname != NULL && dli.dli_fbase != NULL) {
    snprintf(out, outlen, "0x%016" PRIxPTR "  %s",
             (intptr_t)ptr, dli.dli_fname);
    return;
  }

  snprintf(out, outlen, "0x%016" PRIxPTR, (intptr_t)ptr);
}


static void
sappend(char *buf, size_t l, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf + strlen(buf), l - strlen(buf), fmt, ap);
  va_end(ap);
}


/**
 *
 */
static void
dumpstack(void *frames[], int nframes)
{
  char buf[256];
  int i;

  TRAPMSG("STACKTRACE (%d frames)", nframes);

  for(i = 0; i < nframes; i++) {
    addr2text(buf, sizeof(buf), frames[i]);
    TRAPMSG("%s", buf);
  }
}


#ifdef __x86_64__
static const char *
x86_64_regname(int reg)
{
  switch(reg) {
  case REG_R8:    return "r8";
  case REG_R9:    return "r9";
  case REG_R10:   return "r10";
  case REG_R11:   return "r11";
  case REG_R12:   return "r12";
  case REG_R13:   return "r13";
  case REG_R14:   return "r14";
  case REG_R15:   return "r15";
  case REG_RDI:   return "rdi";
  case REG_RSI:   return "rsi";
  case REG_RBP:   return "rbp";
  case REG_RBX:   return "rbx";
  case REG_RDX:   return "rdx";
  case REG_RAX:   return "rax";
  case REG_RCX:   return "rcx";
  case REG_RSP:   return "rsp";
  case REG_RIP:   return "rip";
  case REG_EFL:   return "efl";
  case REG_CSGSFS:   return "csgsfs";
  case REG_ERR:   return "err";
  case REG_TRAPNO:   return "trapno";
  case REG_OLDMASK:   return "oldmask";
  case REG_CR2:   return "cr2";
  default:
    return "???";
  }
}
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

  sigaction(SIGSEGV, &sa, NULL);

  ucontext_t *uc = UC;

  static void *frames[MAXFRAMES];
  char buf[256];
  int nframes = backtrace(frames, MAXFRAMES);
  const char *reason = NULL;

  char prname[17] = {0};

  prctl(PR_GET_NAME, prname, 0, 0, 0);

  TRAPMSG("Signal: %d in thread '%s' - %s ", sig, prname, trap_line);

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

  addr2text(buf, sizeof(buf), si->si_addr);

  TRAPMSG("Fault address %s (%s)", buf, reason ?: "N/A");

  TRAPMSG("Loaded libraries: %s ", libs);

#if defined(__arm__) 
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

#else
  TRAPMSG("Register dump, %d registers: ", NGREG);
  int i;
  for(i = 0; i < NGREG; i++) {
#if __WORDSIZE == 64
    TRAPMSG("[%2d] %7s = 0x%016llx ", i, x86_64_regname(i),
            uc->uc_mcontext.gregs[i]);
#else
    TRAPMSG("[%2d] = 0x%08x ", i, uc->uc_mcontext.gregs[i]);
#endif
  }
#endif
  dumpstack(frames, nframes);
}




static int
iterate_libs_callback(struct dl_phdr_info *info, size_t size, void *data)
{
  if(info->dlpi_name[0])
    sappend(libs, sizeof(libs), "%s ", info->dlpi_name);
  return 0;
}



/**
 *
 */
void
trap_init(void)
{
  struct sigaction sa;
  char self[4096];
  char path[256];
  int r;

  r = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if(r == -1)
    self[0] = 0;
  else
    self[r] = 0;

  snprintf(trap_line, sizeof(trap_line),
	   "EXE: %s, CWD: %s ", self, getcwd(path, sizeof(path)));

  dl_iterate_phdr(iterate_libs_callback, NULL);

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
}



#else

void
trap_init(void)
{
}
#endif

