#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "mta_crypt.h"
#include "mta_rand.h"

#define MAX_LEN 256
#define PIPE_PATH "/mnt/mta/encrypter_pipe"
#define CONFIG_PATH "/mnt/mta/config.txt"
#define LOG_PATH "/var/log/encrypter.log"

typedef struct {
    char name[256];
    int fd;
    int id;   // NEW: store decrypter id from subscription
} Decrypter;

Decrypter decrypters[100];
int num_decrypters = 0;

int password_length;
char current_password[MAX_LEN];
char encrypted_password[MAX_LEN];
int encrypted_length;
int password_version = 0;

FILE *log_file;

void log_info(const char *format, ...) {
    time_t now = time(NULL);
    fprintf(log_file, "[%ld] [SERVER] [INFO] ", now);
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    fprintf(log_file, "\n");
    fflush(log_file);
}

void read_config() {
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) { perror("Failed to open config file"); exit(1); }
    fscanf(f, "%d", &password_length);
    log_info("Password length loaded from config: %d", password_length);
    fclose(f);
    assert(password_length <= MAX_LEN);
}

void generate_password() {
    for (int i = 0; i < password_length; ++i) {
        char c;
        do { MTA_get_rand_data(&c, 1); } while (!isprint((unsigned char)c));
        current_password[i] = c;
    }
    current_password[password_length] = '\0';
}

void encrypt_password(char *key) {
    encrypted_length = 0;
    int key_len = password_length / 8;
    MTA_get_rand_data(key, key_len);
    MTA_encrypt(key, key_len, current_password, password_length,
                encrypted_password, &encrypted_length);
}

void broadcast_password(char* key) {
    password_version++;
    for (int i = 0; i < num_decrypters; ++i) {
        write(decrypters[i].fd, &password_version, sizeof(int));
        write(decrypters[i].fd, &encrypted_length, sizeof(int));
        write(decrypters[i].fd, encrypted_password, encrypted_length);
    }
    key[password_length/8] = '\0';
    log_info("New password: %s, key: %s, Encrypted: %.*s",
             current_password, key, encrypted_length, encrypted_password);
}

// Expect: SUBSCRIBE:<pipe_path>:<decrypter_id>
void handle_subscription(const char *msg) {
    char pipe_name[256];
    int client_id = 0;

    if (sscanf(msg, "SUBSCRIBE:%255[^:]:%d", pipe_name, &client_id) == 2) {
        int fd = open(pipe_name, O_WRONLY);
        if (fd == -1) {
            log_info("Failed to open pipe for new decrypter (id %d): %s", client_id, pipe_name);
            return;
        }

        Decrypter d;
        strncpy(d.name, pipe_name, sizeof(d.name));
        d.name[sizeof(d.name)-1] = '\0';
        d.fd = fd;
        d.id = client_id;
        decrypters[num_decrypters++] = d;

        log_info("Received connection request from decrypter id %d, fifo %s",
                 client_id, pipe_name);

        write(fd, &password_version, sizeof(int));
        write(fd, &encrypted_length, sizeof(int));
        write(fd, encrypted_password, encrypted_length);
    }
}

void handle_password_attempt(const char *msg) {
    int version, client_id;
    char attempt[MAX_LEN];

    // Expect: PASSWORD:<version>:<decrypter_id>:<attempt>
    if (sscanf(msg, "PASSWORD:%d:%d:%255[^\n]", &version, &client_id, attempt) == 3) {
        if (version != password_version) return; // stale

        if (strncmp(attempt, current_password, password_length) == 0) {
            log_info("[OK] Password decrypted successfully by decrypter #%d: %s", client_id, attempt);
            generate_password();
            char key[MAX_LEN];
            encrypt_password(key);
            broadcast_password(key);
        } else {
            log_info("Wrong password attempt from decrypter #%d: %s", client_id, attempt);
        }
    }
}

int main() {
    MTA_crypt_init();

    log_file = fopen(LOG_PATH, "a");
    if (!log_file) { perror("Failed to open log"); exit(1); }

    read_config();

    unlink(PIPE_PATH);
    if (mkfifo(PIPE_PATH, 0666) != 0) { perror("Failed to create named pipe"); exit(1); }

    int server_fd = open(PIPE_PATH, O_RDONLY);
    if (server_fd < 0) { perror("Failed to open pipe"); exit(1); }

    generate_password();
    char key[MAX_LEN];
    encrypt_password(key);
    broadcast_password(key);

    log_info("Listening on /mnt/mta/server_pipe");

    static char inbuf[2048];
    size_t inlen = 0;

    while (1) {
        int n = read(server_fd, inbuf + inlen, sizeof(inbuf) - 1 - inlen);
        if (n > 0) {
            inlen += n;
            inbuf[inlen] = '\0';

            char *start = inbuf;
            char *nl;
            while ((nl = strchr(start, '\n')) != NULL) {
                *nl = '\0';
                if (strncmp(start, "SUBSCRIBE:", 10) == 0) {
                    handle_subscription(start);
                } else if (strncmp(start, "PASSWORD:", 9) == 0) {
                    handle_password_attempt(start);
                }
                start = nl + 1;
            }
            inlen = strlen(start);
            memmove(inbuf, start, inlen);
        } else {
            usleep(100000);
        }
    }

    close(server_fd);
    fclose(log_file);
    return 0;
}


