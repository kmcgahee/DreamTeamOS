#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static int sys_write (int fd, const char *buffer, unsigned int size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
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
