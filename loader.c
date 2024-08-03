#include <bpf/libbpf.h>
#include "controller.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

void fatal_error(const char *message)
{
  puts(message);
  exit(1);
}

bool initialized = false;

static int syscall_logger(void *ctx, void *data, size_t len)
{
  struct inner_syscall_info *info = (struct inner_syscall_info *)data;
  if (!info)
  {
    return -1;
  }

  if (info->mode == SYS_ENTER)
  {
    initialized = true;
    printf("%s(", info->name);
    for (int i = 0; i < info->num_args; i++)
    {
      printf("%p,", info->args[i]);
    }
    printf("\b) = ");
  }
  else if (info->mode == SYS_EXIT)
  {
    if (initialized)
    {
      printf("0x%lx\n", info->retval);
    }
  }
  return 0;
}

int main(int argc, char **argv)
{
  int status;
  struct bpf_object *obj;
  struct bpf_program *enter_prog, *exit_prog;
  struct bpf_map *syscall_map;
  const char *obj_name = "controller.o";
  const char *map_name = "pid_hashmap";
  const char *enter_prog_name = "detect_syscall_enter"; 
  const char *exit_prog_name = "detect_syscall_exit";
  const char *syscall_info_bufname = "syscall_info_buffer";

  if (argc < 2)
  {
    fatal_error("Usage: ./beetrace <path_to_program>");
  }
  const char *file_path = argv[1];

  pid_t pid = fork();
  if (pid == 0)
  {
    int fd = open("/dev/null", O_WRONLY);
    if(fd==-1){
      fatal_error("failed to open /dev/null");
    }
    dup2(fd, 1);
    sleep(2);
    execve(file_path, NULL, NULL);
  }
  else
  {
    printf("Spawned child process with a PID of %d\n", pid);
    obj = bpf_object__open(obj_name);
    if (!obj)
    {
      fatal_error("failed to open the BPF object");
    }
    if (bpf_object__load(obj))
    {
      fatal_error("failed to load the BPF object into kernel");
    }

    enter_prog = bpf_object__find_program_by_name(obj, enter_prog_name);
    exit_prog = bpf_object__find_program_by_name(obj, exit_prog_name);

    if (!enter_prog || !exit_prog)
    {
      fatal_error("failed to find the BPF program");
    }
    if (!bpf_program__attach(enter_prog) || !bpf_program__attach(exit_prog))
    {
      fatal_error("failed to attach the BPF program");
    }
    syscall_map = bpf_object__find_map_by_name(obj, map_name);
    if (!syscall_map)
    {
      fatal_error("failed to find the BPF map");
    }
    const char *key = "child_pid";
    int err = bpf_map__update_elem(syscall_map, key, 10, (void *)&pid, sizeof(pid_t), 0);
    if (err)
    {
      printf("%d", err);
      fatal_error("failed to insert child pid into the ring buffer");
    }

    int rbFd = bpf_object__find_map_fd_by_name(obj, syscall_info_bufname);

    struct ring_buffer *rbuffer = ring_buffer__new(rbFd, syscall_logger, NULL, NULL);

    if (!rbuffer)
    {
      fatal_error("failed to allocate ring buffer");
    }

    if (wait(&status) == -1)
    {
      fatal_error("failed to wait for the child process");
    }

    while (1)
    {
      int e = ring_buffer__consume(rbuffer);
      if (!e)
      {
        break;
      }
      sleep(1);
    }
  }
  return 0;
}