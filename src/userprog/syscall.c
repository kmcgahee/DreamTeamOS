#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"

/* File metadata that allows threads to track different files on the filesystem. */
struct file_descriptor
{
    int handle;            /* Handle # of file (also referred to as a file descriptor) */
    struct file * file;    /* File system information */
    struct list_elem elem; /* List element for list in 'struct thread' */
};

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

static struct file_descriptor * get_file_descriptor (int handle);

static inline void lock_file_system (void);
static inline void unlock_file_system (void);

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
  
  /* Execute the system call and set the return value. */
  f->eax = sc->func (args[0], args[1], args[2]);
}


static int
sys_open (const char *ufile)
{
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
  
  fd = malloc (sizeof *fd);
  if (fd != NULL)
  {
    lock_file_system();
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
    unlock_file_system();
  }
  
  palloc_free_page (kfile);
  return handle;
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
  uint8_t i;
  int8_t temp;
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
  struct thread *cur = thread_current ();
  
  /* Set exit status in thread struct*/
  cur->exit_status = status;
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
    /* Copy filename string from user to kernel memory */
    char *kernel_file = copy_in_string (file);
    bool create_success;
    
    lock_file_system();
    /* Create file with filename in kernel and initial size */
    create_success = filesys_create ( kernel_file, initial_size);
    
    unlock_file_system();
    
    /* Free filename in kernel */
    palloc_free_page (kernel_file);
    
    return create_success; 
}
static bool sys_remove (const char *file)
{
    /* Copy filename string from user to kernel memory */
    char *kernel_file = copy_in_string (file);
    bool remove_success; 
    
    lock_file_system();
    /* Remove file with filename in kernel */
    create_remove = filesys_remove (kernel_file);
    
    unlock_file_system();
    
    /* Free filename in kernel */
    palloc_free_page (kernel_file);
    
    return remove_success;   
}

/* Returns the size, in bytes, of the file open under HANDLE.
   If the handle doesn't exist or an occurs -1 is returned */ 
static int 
sys_filesize (int handle)
{
  int length_of_file = 0;
  struct file_descriptor *fd = get_file_descriptor (handle);
  
  if (!fd)
      return -1;
  
  lock_file_system();
  length_of_file = file_length (fd->file);
  unlock_file_system();
  
  return length_of_file;
}

/* Reads size bytes from the file open as HANDLE into buffer. Returns the number of bytes actually read 
  (0 at end of file), or -1 if the file could not be read. (due to a condition other than end of file).
   The current file position will be advanced by this read. */
static int
sys_read (int handle, void *buffer, unsigned size)
{
  int bytes_read = 0;
  struct file_descriptor *fd = NULL;

  if (!buffer)
      return -1;
  
  if (handle == 0) /* Read in from keyboard */
  {
      for (bytes_read = 0; bytes_read < size; ++bytes_read)
      {
          ((char*)buffer)[bytes_read] = input_getc();
      }
  }
  else
  {
      fd = get_file_descriptor (handle);
      
      if (!fd)
          return -1; /* Error finding file descriptor */
      
      lock_file_system();
      bytes_read = file_read (fd->file, buffer, size);
      unlock_file_system();
  }
    
  return bytes_read;
}

/* Writes size bytes from buffer to the open file descriptor (HANDLE) and advances file position.
 
 Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
 Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file 
 system. Handle of 1 writes to the console. When writing large buffers to the console they output in smaller chunks
 in order to not interleave output between multiple processes. */
static int
sys_write (int handle, const char *buffer, unsigned int size) 
{
  static const unsigned int max_out_buffer_size = 128;
  struct file_descriptor *fd = NULL;
  unsigned int current_size = 0;
  unsigned int size_left = size;
  int bytes_written = 0;
  
  if (!buffer)
    return -1;

  if (handle == 1) /* Write to console */
  {
    while (size_left > 0)
    {  
      current_size = min(size_left, max_out_buffer_size);  
      putbuf (buffer + bytes_written, current_size);
      bytes_written += current_size;
      size_left -= current_size;
    }
  }
  else
  {
    fd = get_file_descriptor (handle);
    
    if (!fd)
      return -1; /* Error finding file descriptor */
    
    lock_file_system();
    bytes_written = file_write (fd->file, buffer, size);
    unlock_file_system();
  }
  
  return bytes_written;
}

/* Changes the next byte to be read or written in open file HANLDE to position,
  expressed in bytes from the beginning of the file.
  A seek past the current end of a file is not an error.
  A later read obtains 0 bytes, indicating end of file.
  A later write currently will cause an error due to fixed file sizes. */
static void
sys_seek (int handle, unsigned position)
{
  struct file_descriptor *fd = get_file_descriptor (handle);
    
  if (!fd)
    return; /* Error finding file descriptor */
  
  lock_file_system();
  file_seek (fd->file, position);
  unlock_file_system();
}

/* Returns the position of the next byte to be read or written in open file HANDLE,
   expressed in bytes from the beginning of the file. */
static unsigned
sys_tell (int handle)
{
  struct file_descriptor *fd = get_file_descriptor (handle);
  unsigned int pos = 0;
  
  if (!fd)
    return 0; /* Error finding file descriptor */
    
  lock_file_system();
  pos = file_tell (fd->file);
  unlock_file_system();
    
  return pos;
}

/* Closes file descriptor HANDLE. Exiting or terminating a process implicitly closes
   all its open file descriptors, as if by calling this function for each one. */
static void
sys_close (int handle)
{
  struct file_descriptor *fd = get_file_descriptor (handle);
    
  if (!fd)
    return; /* Error finding file descriptor */
  
  lock_file_system();
  file_close (fd->file);
  unlock_file_system();
}

/* Returns the file descriptor information for current thread corresponding to HANDLE.  
   If the HANDLE doesn't correspond to any known file descriptor or if an error occurs
   then null is returned. */
static struct file_descriptor *
get_file_descriptor (int handle)
{
    struct file_descriptor *fd = NULL;
    struct thread *cur = thread_current();
    struct list_elem *e = NULL;

    /* Try to find matching handle in current threads list. */
    for (e = list_begin (&cur->fds);
         e != list_end (&cur->fds);
         e = list_next (e))
    {
        fd = list_entry (e, struct file_descriptor, elem);
        
        if (fd->handle == handle)
            return fd;
    }
    
    return NULL; /* Couldn't find matching handle */
}

/* Locks the file system to be owned by current thread.
   Will block if lock is already owned by another thread. */
static inline void
lock_file_system (void)
{
    lock_acquire (&fs_lock);
}

/* Unlock file system so other threads can use it. */
static inline void
unlock_file_system (void)
{
    lock_release (&fs_lock);
}
