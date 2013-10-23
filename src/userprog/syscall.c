#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static struct lock fs_lock;

static void syscall_handler (struct intr_frame *);

static int sys_write (int, const char *, unsigned int);
static void sys_halt (void);
static void sys_exit (int);
static pid_t sys_exec (const char *);
static int sys_wait (pid_t);
static bool sys_create (const char *, unsigned);
static bool sys_remove (const char *);
static int sys_open (const char *);
static int sys_filesize (int);
static int sys_read (int, void *, unsigned);
static void sys_seek (int, unsigned);
static unsigned sys_tell (int); 
static void sys_close (int);

static void copy_in (void *, const void *, size_t);
static char * copy_in_string (const char *us);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  typedef int syscall_function (int, int, int);
  
  /* A system call. */
  struct syscall
    {
      size_t arg_cnt;          /* Number of arguments. */
      syscall_function *func;  /* Implementation. */
    };
  
  
  /* Table of system calls. */
  static const struct syscall syscall_table[] =
    {
      /* Project 2 */
      {0, (syscall_function *) sys_halt},
      {1, (syscall_function *) sys_exit},
      {1, (syscall_function *) sys_exec},
      {1, (syscall_function *) sys_wait},
      {2, (syscall_function *) sys_create},
      {1, (syscall_function *) sys_remove},
      {1, (syscall_function *) sys_open},
      {1, (syscall_function *) sys_filesize},
      {3, (syscall_function *) sys_read},
      {3, (syscall_function *) sys_write},
      {2, (syscall_function *) sys_seek},
      {1, (syscall_function *) sys_tell},
      {1, (syscall_function *) sys_close},
    };
  
  const struct syscall *sc;
  unsigned call_nr;
  int args[3];
  /* Get the system call. */
  copy_in (&call_nr, f->esp, sizeof call_nr);
  if( call_nr >= sizeof syscall_table / sizeof *syscall_table)
  {
    thread_exit ();
  }
  sc = syscall_table + call_nr;
  
  /* Get the system call arguments */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);
  
  /* Execute the system call,
     and set the return value. */
  f->eax = sc->func (args[0], args[1], args[2]);
}

// TODO: comment, check, & complete code
static int
sys_open (const char *ufile)
{
/* COMMENT OUT */
#if 0
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
  
  fd = malloc (sizeof *fd);
  if (fd != NULL)
  {
    lock_acquire (&fs_lock);
    fd->file = filesys_open (kfile);
    if (fd->file != NULL)
    {
      struct thread *cur = thread_current();
      handle = fd->handle = cur->next_handle++;
      list_push_front (&cur->fds, &fd->elem);
    }
    else
    {
      free (fd);
    }
    lock_release (&fs_lock);
  }
  
  palloc_free_page (kfile);
  return handle;
#endif
/* END COMMENT */

printf( "sys_open() not implemented.\n" );
thread_exit();
}

/* Writes size bytes from buffer to the open file descripter (fd).
 
 Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
 Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file 
 system. Fd 1 writes to the console. When writing large buffers to the console they output in smaller chunks
 in order to not interleave output between multiple processes. */
static int
sys_write (int fd, const char *buffer, unsigned int size) 
{
  static const unsigned int max_out_buffer_size = 128;
  unsigned int current_size = 0;
  int bytes_written = 0;
  
  // TODO: Handle buffer being NULL
  // TODO: Handle bad file descripters

  // TODO: Use Filesystem Lock (fs_lock)
  if (fd == 1) /* Write to console */
  {
    bytes_written = size; /* Always write out all bytes */
    while (size > 0)
    {  
      current_size = min(size, max_out_buffer_size);  
      putbuf(buffer, size);
      size -= current_size;
    }
  }
  else
  {
    // TODO: Write out to file.
  }
  
  return bytes_written;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Copies byte-by-byte from user source to kernel destination.
   Upon failure to copy (such as invalid user ptr or seg fault),
   the calling thread will exit.                                */
static void
copy_in (void * dest, const void * src, size_t size)
{
  // TODO: optimize / improve structure
  int i;
  int8_t temp;
  const uint8_t * data = src;
  uint8_t * data_dest = dest;
  for( i=0; i < size; i++ )
  {
    /* Verify source address is below PHYS_BASE */
    /* and byte is successfully copied          */
    if( src < PHYS_BASE )
    {
      temp = get_user( src );
      if( temp < 0 )
      {
        /* Segfault, exit thread */
        thread_exit();
      }
      
      *((uint8_t*)dest) = temp;
    }
    else
    {
      /* User memory ptr invalid */
      thread_exit();
    }

    /* Increment ptr to get next byte */
    dest++;
    src++;
  }
}

/* Copies user string to kernel memory.
   It allocates a page in kernel memory, so this
   limits the user string to size PGSIZE         
   Upon error, will exit thread.                */
static char * copy_in_string (const char *us)
{
  char * ks;
  int i;

  // TODO: add comments, possibly optimize.
  ks = palloc_get_page(0);
  if( ks == NULL )
  {
    thread_exit();
  }
  
  for( i = 0; i < PGSIZE; i++ )
  {
    if( us < PHYS_BASE )
    {
      ks[i] = get_user( us );
      if( ks[i] < 0 )
      {
        palloc_free_page (ks);
        thread_exit();
      }
      
      if( ks[i] == '\0' )
      {
        return ks;
      }
    }
    else
    {
      palloc_free_page (ks);
      thread_exit();
    }
  }

  ks[PGSIZE - 1] = '\0';
  return ks;
}

static void
sys_halt (void)
{
  printf( "sys_halt() not implemented.\n" );
  thread_exit();
}

static void
sys_exit (int status)
{
  printf( "sys_exit() not implemented.\n" );
  thread_exit();
}

static pid_t
sys_exec (const char *file)
{
  printf( "sys_exec() not implemented.\n" );
  thread_exit();
}

static int sys_wait (pid_t pid)
{
  printf( "sys_wait() not implemented.\n" );
  thread_exit();
}
static bool sys_create (const char *file, unsigned initial_size)
{
  printf( "sys_create() not implemented.\n" );
  thread_exit();
}
static bool sys_remove (const char *file)
{
  printf( "sys_remove() not implemented.\n" );
  thread_exit();
}

static int sys_filesize (int fd)
{
  printf( "sys_filesize() not implemented.\n" );
  thread_exit();
}

static int sys_read (int fd, void *buffer, unsigned size)
{
  printf( "sys_read() not implemented.\n" );
  thread_exit();
}

static void sys_seek (int fd, unsigned position)
{
  printf( "sys_seek() not implemented.\n" );
  thread_exit();
}

static unsigned sys_tell (int fd)
{
  printf( "sys_tell() not implemented.\n" );
  thread_exit();
}

static void sys_close (int fd)
{
  printf( "sys_close() not implemented.\n" );
  thread_exit();
}


