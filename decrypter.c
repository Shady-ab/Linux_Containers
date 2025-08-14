#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <stdarg.h>

#include "mta_crypt.h"
#include "mta_rand.h"

#define MAX_LEN 256
#define PIPE_DIR "/mnt/mta"
#define SERVER_PIPE "/mnt/mta/encrypter_pipe"
#define CONFIG_PATH "/mnt/mta/config.txt"
#define LOG_PATH "/var/log/decrypter.log"

char decrypter_pipe_path[256];
FILE *log_file;
int decrypter_id = 0;
int password_length;
static int current_version = 0;

void log_info(const char *format, ...) {
    time_t now = time(NULL);
    fprintf(log_file, "[%ld] [CLIENT #%d] [INFO] ", now, decrypter_id);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file);
}

void read_config() {
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) {
        perror("Failed to open config file");
        exit(1);
    }
    fscanf(f, "%d", &password_length);
    log_info("Password length loaded from config: %d", password_length);
    fclose(f);
    assert(password_length <= MAX_LEN);
}

void create_unique_pipe() {
    for (int i = 1; i < 100; ++i) {
        snprintf(decrypter_pipe_path, sizeof(decrypter_pipe_path), "%s/decrypter_pipe_%d", PIPE_DIR, i);
        if (access(decrypter_pipe_path, F_OK) == -1) {
            if (mkfifo(decrypter_pipe_path, 0666) == 0) {
                decrypter_id = i;
                log_info("Created pipe: %s", decrypter_pipe_path);
                return;
            }
        }
    }
    perror("Failed to create unique pipe");
    exit(1);
}

void send_subscription() {
    int server_fd = open(SERVER_PIPE, O_WRONLY);
    if (server_fd == -1) {
        perror("Cannot open server pipe");
        exit(1);
    }

    char message[300];
    snprintf(message, sizeof(message), "SUBSCRIBE:%s:%d\n", decrypter_pipe_path, decrypter_id);
    write(server_fd, message, strlen(message));
    close(server_fd);

    log_info("Sent connect request to server (id %d)", decrypter_id);
}

int is_printable(const char *buf, int len) {
    for (int i = 0; i < len; ++i)
        if (!isprint((unsigned char)buf[i]))
            return 0;
    return 1;
}

int main() {
    MTA_crypt_init();

    log_file = fopen(LOG_PATH, "a");
    if (!log_file) {
        perror("Failed to open log");
        exit(1);
    }

    read_config();
    create_unique_pipe();
    send_subscription();

    int fd = open(decrypter_pipe_path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open own pipe");
        exit(1);
    }

    char encrypted[MAX_LEN], key[MAX_LEN];
    int enc_len;
    int iterations = 0;

    while (1) {
        int incoming_version = -1;
        int check_fd = open(decrypter_pipe_path, O_RDONLY | O_NONBLOCK);
        if (check_fd != -1) {
            if (read(check_fd, &incoming_version, sizeof(int)) > 0 && incoming_version != current_version) {
                current_version = incoming_version;
                int new_len = 0;
                if (read(check_fd, &new_len, sizeof(int)) > 0 && new_len > 0 && new_len < MAX_LEN) {
                    char new_encrypted[MAX_LEN];
                    int total = 0;
                    while (total < new_len) {
                        int n = read(check_fd, new_encrypted + total, new_len - total);
                        if (n > 0) total += n;
                        else break;
                    }
                    if (total == new_len) {
                        memcpy(encrypted, new_encrypted, new_len);
                        enc_len = new_len;
                        iterations = 0;
                        log_info("Received new encrypted password: %.*s", enc_len, encrypted);
                    }
                }
            }
            close(check_fd);
        }

        int key_len = password_length / 8;
        MTA_get_rand_data(key, key_len);

        char attempt[MAX_LEN];
        int dec_len = 0;

        MTA_decrypt(key, key_len, encrypted, enc_len, attempt, &dec_len);
        iterations++;

        if (!is_printable(attempt, dec_len))
            continue;

        attempt[dec_len] = '\0';

        int server_fd = open(SERVER_PIPE, O_WRONLY);
        if (server_fd != -1) {
            char message[300];
            snprintf(message, sizeof(message), "PASSWORD:%d:%d:%s\n", current_version, decrypter_id, attempt);
            write(server_fd, message, strlen(message));
            close(server_fd);
        }

        log_info("Decrypted password: %s (in %d iterations)", attempt, iterations);

        usleep(50000);
    }

    close(fd);
    fclose(log_file);
    return 0;
}


