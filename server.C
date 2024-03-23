#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

#define MAX_CLIENTS 10
#define BUFFER_SZ 2048
#define MESSAGE_STORAGE_FILE "./messages.txt"
#define MESSAGE_DELIMITER "\n"

// user names and password registration
const char **usernames;
const char **passwords;
// client count
static _Atomic unsigned int cli_count = 0;
static int uid = 10;

// client socket
typedef struct {
    struct sockaddr_in address;
    int sockfd;
    int uid;
    char name[32];
    SSL *ssl;
} client_t;

// client connections
client_t *clients[MAX_CLIENTS];
SSL_CTX *ctx;

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// function declaration send message to sender
void send_message_sender(char *s, int uid);
// Function declaration to trim newline characters
void str_trim_lf(char* arr, int length);

int num_users = 0;
int max_users = 0;

// check and register user
int add_user(const char *username, const char *password) {
    // check if the max_users limit is reached
    if (num_users == max_users) {
        return 3;
    }
    if (num_users >= max_users) {
        // If the array is full, reallocate memory to double its size
        max_users = (max_users == 0) ? 1 : max_users * 2;
        usernames = (const char **)realloc(usernames, max_users * sizeof(const char *));
        passwords = (const char **)realloc(passwords, max_users * sizeof(const char *));
        if (!usernames || !passwords) {
            perror("Error reallocating memory");
            exit(EXIT_FAILURE);
        }
    }
    bool isUsernameExisting = false;
    // check if user name is existing
    for (int i = 0; i < num_users; ++i) {
        if (strcmp(username, usernames[i]) == 0) {
            isUsernameExisting = true;
            break;
        }
    }
    if (isUsernameExisting) {
        // username exists
        return 2;
    }

    // username doesnt exist. add new username
    // Allocate memory for the new username and password
    usernames[num_users] = strdup(username);
    passwords[num_users] = strdup(password);
    if (!usernames[num_users] || !passwords[num_users]) {
        perror("Error allocating memory");
        exit(EXIT_FAILURE);
    }
    num_users++;
    return 0;
}

// function to send previous messages from the persistent store
void send_prev_messages(int clid) {
    FILE *file = fopen(MESSAGE_STORAGE_FILE, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }
    
    // Create a buffer to store the lines of text
    char prevMsg[BUFFER_SZ];

    // Read the file line by line
    while (fgets(prevMsg, sizeof(prevMsg), file) != NULL) {
        str_trim_lf(prevMsg, strlen(prevMsg));
        // send all the messages to the client
        send_message_sender(prevMsg, clid);
    }

    fclose(file);
}

// function to persist the message into a store
void store_message(const char *message) {
    FILE *file = fopen(MESSAGE_STORAGE_FILE, "a");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }
    fprintf(file, "%s", message);
    fclose(file);
}

// authenticate user name and password
int authenticate_user(const char *username, const char *password) {
    bool userFound = false;
    // check if username is existing
    for (int i = 0; i < num_users; ++i) {
        if (strcmp(username, usernames[i]) == 0) {
            userFound = true;
        }
    }
    // username is not found. send username not found status code 2
    if (userFound == false){
        printf("user %s not found\n", username);
        return 2;
    }

    // check if user name and password match
    for (int i = 0; i < num_users; ++i) {
        if (strcmp(username, usernames[i]) == 0 && strcmp(password, passwords[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// overwrite the std out with the > prompt
void str_overwrite_stdout() {
    printf("\r%s", "> ");
    fflush(stdout);
}

// trim Carriage return and line feed
void str_trim_lf(char *arr, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (arr[i] == '\n') {
            arr[i] = '\0';
            break;
        }
    }
}

// client socket address
void print_client_addr(struct sockaddr_in addr) {
    printf("%d.%d.%d.%d",
           addr.sin_addr.s_addr & 0xff,
           (addr.sin_addr.s_addr & 0xff00) >> 8,
           (addr.sin_addr.s_addr & 0xff0000) >> 16,
           (addr.sin_addr.s_addr & 0xff000000) >> 24);
}

// queue the client
void queue_add(client_t *cl) {
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (!clients[i]) {
            clients[i] = cl;
            break;
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

// remove from the queue
void queue_remove(int uid) {
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i]) {
            if (clients[i]->uid == uid) {
                clients[i] = NULL;
                break;
            }
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

// send message only to sender
void send_message_sender(char *s, int uid) {
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i]) {
            if (clients[i]->uid == uid) {
                SSL_write(clients[i]->ssl, s, strlen(s));
            }
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

// send message to all except sender
void send_message(char *s, int uid) {
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i]) {
            if (clients[i]->uid != uid) {
                SSL_write(clients[i]->ssl, s, strlen(s));
            }
        }
    }

    pthread_mutex_unlock(&clients_mutex);
}

// function to handle client messages
void *handle_client(void *arg) {
    char buff_out[BUFFER_SZ];
    char name[32];
    char pwd[32];
    int leave_flag = 0;
    char msg[BUFFER_SZ];
    char currentTime[20];
    int authResponse = 0;
    cli_count++;
    client_t *cli = (client_t *) arg;
    // check user name if entered
    if (SSL_read(cli->ssl, name, 32) <= 0 || strlen(name) < 2 || strlen(name) >= 32 - 1) {
        printf("Didn't enter the name.\n");
        leave_flag = 1;
    } else {
        str_trim_lf(name, strlen(name));
        strcpy(cli->name, name);
        // check password if entered        
        if (SSL_read(cli->ssl, pwd, 32) <= 0 || strlen(pwd) < 2 || strlen(pwd) >= 32 - 1) {
            printf("Didn't enter the password.\n");
            leave_flag = 1;  
        }
        str_trim_lf(pwd, strlen(pwd));
        // authenticate user name and password
        authResponse = authenticate_user(name, pwd);
        // check the result
        switch(authResponse)
        {
            // auth failed
            case 0: 
                sprintf(buff_out, "Incorrect username or password. Please login again\n");
                send_message_sender(buff_out, cli->uid);
                leave_flag = 1;
                break;
            // auth successful
            case 1:
                time_t now = time(NULL);
                strftime(currentTime, 20, "%d-%m-%Y %H:%M:%S", localtime(&now));
                sprintf(buff_out, "%s has joined\n", cli->name);
                printf("%s", buff_out);
                send_message(buff_out, cli->uid);
                send_message_sender(buff_out, cli->uid);
                printf("sending previous messages now to %s\n", cli->name);
                sprintf(msg, "%s %s has joined\n", currentTime, cli->name);
                store_message(msg);
                // send prev messages
                send_prev_messages(cli->uid);
                break;
            // user not found
            case 2:
                sprintf(buff_out, "The username you entered is not found.\n");
                send_message_sender(buff_out, cli->uid);
                if (SSL_read(cli->ssl, name, 32) <= 0 || strlen(name) < 2 || strlen(name) >= 32 - 1) {
                    printf("User did not register.\n");
                    leave_flag = 1;
                    break;
                } else {
                    str_trim_lf(name, strlen(name));
                    strcpy(cli->name, name);
                    if (SSL_read(cli->ssl, pwd, 32) <= 0 || strlen(pwd) < 2 || strlen(pwd) >= 32 - 1) {
                        printf("User did not set the password.\n");
                        leave_flag = 1;     
                        break;
                    }
                    str_trim_lf(pwd, strlen(pwd));
                }

                now = time(NULL);
                strftime(currentTime, 20, "%d-%m-%Y %H:%M:%S", localtime(&now));
                // add new user registration
                int add_user_result = add_user(name, pwd);
                switch (add_user_result) {
                    // add user is successful
                    case 0:
                        sprintf(buff_out, "New user %s registration is completed.\n", name);
                        send_message_sender(buff_out, cli->uid);
                        printf("%s", buff_out);
                        bzero(buff_out, BUFFER_SZ);
                        sprintf(buff_out, "%s has joined\n", cli->name);
                        printf("%s", buff_out);
                        send_message(buff_out, cli->uid);
                        
                        sprintf(msg,  "%s %s has joined\n", currentTime, cli->name);
                        store_message(msg);
                        // send prev messages
                        send_prev_messages(cli->uid);
                        break;
                    // add user is failed
                    case 1:
                        sprintf(buff_out, "Could not register. Please try again later.\n");
                        send_message_sender(buff_out, cli->uid);
                        printf("%s", buff_out);
                        leave_flag = 1;
                        break;
                    // username is already taken by someone else. prompt to choose new username
                    case 2:
                        sprintf(buff_out, "Username is already taken. Please choose a different user name.\n");
                        send_message_sender(buff_out, cli->uid);
                        printf("%s", buff_out);
                        leave_flag = 1;
                        break;
                    // max user limit reached. cant register
                    case 3:
                        sprintf(buff_out, "Max users limit reached. Please try again later.\n");
                        send_message_sender(buff_out, cli->uid);
                        printf("%s", buff_out);
                        leave_flag = 1;
                        break;
                }               
                
            default:
                break;
        }
    }
    // reset buffers
    memset(name, 0, sizeof(name));
    memset(pwd, 0, sizeof(pwd));
    bzero(buff_out, BUFFER_SZ);
    bzero(currentTime, 20);
    bzero(msg, BUFFER_SZ);

    while (1) {
        if (leave_flag) {
            break;
        }

        int receive = SSL_read(cli->ssl, buff_out, BUFFER_SZ);
        // check if any message received
        if (receive > 0) {
            if (strlen(buff_out) > 0) {
                // send the message to all the clients except the sender
                time_t now = time(NULL);
                strftime(currentTime, 20, "%d-%m-%Y %H:%M:%S", localtime(&now));
                str_trim_lf(buff_out, strlen(buff_out));
                printf("%s\n", buff_out);
                sprintf(msg, "%s\n", buff_out);                
                send_message(msg, cli->uid);
                // save the message with timestamp in persistent store
                bzero(msg, BUFFER_SZ);
                sprintf(msg, "%s %s\n", currentTime, buff_out);
                store_message(msg);
            }
        } else if (receive == 0 || strcmp(buff_out, "exit") == 0) {
            // if anyone leaves, broadcast the message
            time_t now = time(NULL);
            strftime(currentTime, 20, "%d-%m-%Y %H:%M:%S", localtime(&now));
            sprintf(buff_out, "%s has left\n", cli->name);
            printf("%s", buff_out);
            send_message(buff_out, cli->uid);
            // save the message with timestamp in persistent store
            sprintf(msg, "%s %s has left\n", currentTime, cli->name);
            store_message(msg);
            leave_flag = 1;
        } else {
            printf("ERROR: -1\n");
            leave_flag = 1;
        }
        // reset the buffer
        bzero(currentTime, 20);
        bzero(msg, BUFFER_SZ);
        bzero(buff_out, BUFFER_SZ);
    }

    // close the socket and free up
    close(cli->sockfd);
    SSL_free(cli->ssl);
    queue_remove(cli->uid);
    free(cli);
    cli_count--;
    pthread_detach(pthread_self());

    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <port> <maxusers>\n", argv[0]);
        return EXIT_FAILURE;
    }
    // max users to register
    max_users = atoi(argv[2]);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    // bind the cert
    if (SSL_CTX_use_certificate_file(ctx, "./server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    // use private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "./cert.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    // allocate memory
    usernames = (const char **)malloc(max_users * sizeof(const char *));
    passwords = (const char **)malloc(max_users * sizeof(const char *));

    // local host
    char *ip = "127.0.0.1";
    // port
    int port = atoi(argv[1]);
    int option = 1;
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    pthread_t tid;
    // setup the socket
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    signal(SIGPIPE, SIG_IGN);

    if (setsockopt(listenfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR), (char *) &option, sizeof(option)) < 0) {
        perror("ERROR: setsockopt failed");
        return EXIT_FAILURE;
    }

    if (bind(listenfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR: Socket binding failed");
        return EXIT_FAILURE;
    }

    if (listen(listenfd, 10) < 0) {
        perror("ERROR: Socket listening failed");
        return EXIT_FAILURE;
    }

    printf("=== WELCOME TO THE CHATROOM ===\n");

    while (1) {
        socklen_t clilen = sizeof(cli_addr);
        // check connection and accept
        connfd = accept(listenfd, (struct sockaddr *) &cli_addr, &clilen);

        if ((cli_count + 1) == MAX_CLIENTS) {
            printf("Max clients reached. Rejected: ");
            print_client_addr(cli_addr);
            printf(":%d\n", cli_addr.sin_port);
            close(connfd);
            continue;
        }
        // ssl connection 
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, connfd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(connfd);
            continue;
        }
        // to keep track of the clients connected
        client_t *cli = (client_t *) malloc(sizeof(client_t));
        cli->address = cli_addr;
        cli->sockfd = connfd;
        cli->uid = uid++;
        cli->ssl = ssl;

        queue_add(cli);
        // handle the messages
        pthread_create(&tid, NULL, &handle_client, (void *) cli);

        sleep(1);
    }
    // close the SSL and free up socket
    SSL_CTX_free(ctx);
    close(listenfd);

    return EXIT_SUCCESS;
}
