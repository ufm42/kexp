# kexp

# How to use
```
1. Jailbreak from userland process

2. Create executable shared memory region
   exec_fd = jitshm_create(name = "", size = ALIGN_UP(kexp.length, PAGE_SIZE), permissions = RWX)

3. Map executable memory into process space
   entry_addr = mmap(
       address = 0,
       size = ALIGN_UP(kexp.length, PAGE_SIZE),
       permissions = RWX,
       flags = 0,
       fd = exec_fd,
       offset = 0
   )

4. Copy payload machine code into mapped memory
   memcpy(
       destination = entry_addr,
       source = kexp.buffer,
       size = kexp.length
   )

5. Allocate structure for kexp arguments
   kexp_args = allocate(0x28 bytes)

6. Fill kexp argument structure
    kexp_args:
      +0x00 = master_pipe[0]
      +0x04 = master_pipe[1]
      +0x08 = victim_pipe[0]
      +0x0C = victim_pipe[1]
      +0x10 = allproc
      +0x18 = elfldr_addr
      +0x20 = elfldr_size

7. Create new thread
    result = pthread_create(
        thread_handle_out = pthread_addr_out,
        attributes = NULL,
        start_routine = entry_addr,
        argument = kexp_args
    )

8. Wait for thread to finish
    pthread_addr = read_u64(pthread_addr_out)
    result = pthread_join(
        thread = pthread_addr,
        return_value_out = ret_addr
    )

9. Read thread return value
    ret = *ret_addr

10. Log return value
    print(ret)

11. Free kexp argument storage
    free(kexp_args)

12. Free return value storage
    free(ret_addr)
```

# Credits
Special thanks to:
- TheFloW
- Specter
- Gezine
- cow
- sb
- Dr.Yenyen
- flat_z
