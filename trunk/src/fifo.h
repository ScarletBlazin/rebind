#define FIFO_FILE               "/tmp/fifo"
#define MAX_READ_SIZE           128

void fifo_cleanup();
void destroy_fifo(char *fifo);
int read_from_fifo(char *fifo);
void write_to_fifo(int id);
void close_fifo(FILE *fd);
FILE *open_fifo(char *fifo, char *mode);
char *create_fifo(char *host_name);
