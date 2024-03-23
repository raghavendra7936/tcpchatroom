#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <termios.h>
#include <ctype.h>
#include <stdbool.h>

#define LENGTH 2048
#define PRESENCE_INTERVAL 60 // Presence signal interval in seconds
#define CONFIG_FILE "config.txt"

volatile sig_atomic_t flag = 0;
int sockfd = 0;
char name[32];
char pwd[32];
SSL_CTX *ctx;
SSL *ssl;

int getch() {
    int ch;
    // struct to hold the terminal settings
    struct termios old_settings, new_settings;
    // take default setting in old_settings
    tcgetattr(STDIN_FILENO, &old_settings);
    // make of copy of it (Read my previous blog to know 
    // more about how to copy struct)
    new_settings = old_settings;
    // change the settings for by disabling ECHO mode
    // read man page of termios.h for more settings info
    new_settings.c_lflag &= ~(ICANON | ECHO);
    // apply these new settings
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    // now take the input in this mode
    ch = getchar();
    // reset back to default settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    return ch;
}


void str_overwrite_stdout() {
    printf("\r%s", "> ");
    fflush(stdout);
}

// Function to send presence signal to server
void send_presence_signal() {
    // Send presence signal to server (e.g., "PING")
    send(sockfd, "PING", strlen("PING"), 0);
}


// Function to trim newline characters
void str_trim_lf(char* arr, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (arr[i] == '\n') {
            arr[i] = '\0';
            break;
        }
    }
}

void catch_ctrl_c_and_exit(int sig) {
    flag = 1;
}

void send_msg_handler() {
    char message[LENGTH] = {};
    char buffer[LENGTH + 32] = {};

    while (1) {
        str_overwrite_stdout();
        fgets(message, LENGTH, stdin);
        str_trim_lf(message, LENGTH);

        if (strcmp(message, "exit") == 0) {
            break;
        } else {
            sprintf(buffer, "%s: %s\n", name, message);
            SSL_write(ssl, buffer, strlen(buffer));
        }

        bzero(message, LENGTH);
        bzero(buffer, LENGTH + 32);
        // Send presence signal at regular intervals
        //sleep(PRESENCE_INTERVAL);
        //send_presence_signal();
    }
    catch_ctrl_c_and_exit(2);
}

void recv_msg_handler() {
    // function to handle messages received from server
    char message[LENGTH] = {};
    while (1) {
        int receive = SSL_read(ssl, message, LENGTH);
        if (receive > 0) {
            str_trim_lf(message, LENGTH);
            printf("%s\n", message);
            str_overwrite_stdout();
        } else if (receive == 0) {
            break;
        } else {
            // -1
        }
        memset(message, 0, sizeof(message));
    }
}

// open the ssl connection
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// cleanup and free the ssl connection
void cleanup_openssl() {
    EVP_cleanup();
}

// SSL context
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// configure the SSL context
void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
}

// function to get user login and password including new registration
void getuserlogin(bool isNewReg, char *name, char *pwd) {
    char promptName[50];
    char promptPwd[50];
    signal(SIGINT, catch_ctrl_c_and_exit);
    if (isNewReg){
        sprintf(promptName, "Register your username: ");
        sprintf(promptPwd, "Set your password: ");
    }
    else {
        sprintf(promptName, "Please enter your name: ");
        sprintf(promptPwd, "Enter your password: ");
    }
    bzero(pwd, 32);
    while (1) {
        bzero(name, 32);
        printf("%s", promptName);
        fgets(name, 32, stdin);
        str_trim_lf(name, strlen(name));
        if (strlen(name) > 32 || strlen(name) < 2) {
            printf("Name must be less than 30 and more than 2 characters.\n");
        }
        else {
            break;
        }
    }

    int i = 0;
    int ch;
    while (1) {
        bzero(pwd, 32);
        printf("%s", promptPwd);
        while ((ch = getch()) != '\n') {
            if (ch == 127 || ch == 8) { // handle backspace
                if (i != 0) {
                    i--;
                    printf("\b \b");
                }
            } else {
                pwd[i++] = ch;
                // echo the '*' to get feel of taking password 
                printf("*");
            }
        }
        pwd[i] = '\0';
        //fgets(pwd, 32, stdin);
        str_trim_lf(pwd, strlen(pwd));

        if (strlen(pwd) > 32 || strlen(pwd) < 2) {
            printf("\nPassword must be less than 30 and more than 2 characters.\n");
            //exit(EXIT_FAILURE);
        }
        else {
            break;
        }
    }
}


int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }
    // ip address & port of the server
    char *ip = argv[1];
    int port = atoi(argv[2]);
    //char *username = argv[3];

    signal(SIGINT, catch_ctrl_c_and_exit);

    getuserlogin(false, name, pwd);
    // open the ssl connection
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port = htons(port);

    // check connection to server
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        perror("Unable to connect to server");
        close(sockfd);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    // check ssl connection if it is established
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }
    // send the name and password
    SSL_write(ssl, name, strlen(name));
    SSL_write(ssl, pwd, strlen(pwd));

    // get authentication response
    char response[LENGTH] = {};
    char regMessage[LENGTH] = {};
    char option;

    int receive = SSL_read(ssl, response, LENGTH);
    if (receive > 0) {
        // check the response
        if (strcmp(response, "Incorrect username or password. Please login again\n") == 0) {
            printf("\n%s", response);
            str_overwrite_stdout();
            close(sockfd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            cleanup_openssl();
            exit(EXIT_FAILURE);
        }
        else if (strcmp(response, "The username you entered is not found.\n") == 0) {
            printf("\nThe username you entered is not found.\n");
            // prompt to register
            while(1)
            {
                printf("Do you want to register? (y|n) ");
                scanf(" %c", &option);
                getchar();
                
                if (tolower(option) == 'y' || tolower(option) == 'n')
                {
                    break;
                }
            }
            if (tolower(option) == 'y') {
                getuserlogin(true, name, pwd);

                while (1) {
                    bzero(response, LENGTH);
                    // send the user name and password
                    SSL_write(ssl, name, strlen(name));
                    SSL_write(ssl, pwd, strlen(pwd));
                    // wait for response
                    receive = SSL_read(ssl, response, LENGTH);
                    if (receive > 0) {
                        // registration success message to compare
                        sprintf(regMessage, "New user %s registration is completed.\n", name);
                        // check the registration response
                        if (strcmp(response, "Username is already taken. Please choose a different user name.\n") == 0) {
                            str_overwrite_stdout();
                            close(sockfd);
                            SSL_free(ssl);
                            SSL_CTX_free(ctx);
                            cleanup_openssl();
                            exit(EXIT_FAILURE);                        }
                        else if (strcmp(response, regMessage) == 0) {
                            printf("\nYou have successfully registered!\n");
                            break;
                        }
                        else {
                            printf("Unable to register. Please try again.\n");
                            str_overwrite_stdout();
                            close(sockfd);
                            SSL_free(ssl);
                            SSL_CTX_free(ctx);
                            cleanup_openssl();
                            exit(EXIT_FAILURE);
                        }
                    }
                }
            }
            else {
                str_overwrite_stdout();
                close(sockfd);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                cleanup_openssl();
                exit(EXIT_FAILURE);
            }
        }
    }

    printf("\n=== WELCOME TO THE CHATROOM ===\n");

    pthread_t send_msg_thread;
    // send message thread
    if (pthread_create(&send_msg_thread, NULL, (void *) send_msg_handler, NULL) != 0) {
        perror("pthread_create");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    pthread_t recv_msg_thread;
    // receive message thread
    if (pthread_create(&recv_msg_thread, NULL, (void *) recv_msg_handler, NULL) != 0) {
        perror("pthread_create");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    while (1) {
        if (flag) {
            printf("\nBye\n");
            break;
        }
    }
    return EXIT_SUCCESS;
}
