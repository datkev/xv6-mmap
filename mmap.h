struct maplist {
  struct maplist *next;
  void *addr;
  int len;
  int prot;
  int flags;
  int offset;
  int fd; // struct file *
  int allocated;
};
