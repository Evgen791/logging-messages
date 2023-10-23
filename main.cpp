#include <iostream>
#include <cstring>
#include <thread>
#include <chrono>
#include <sqlite3.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt/BCrypt.hpp>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <fstream>
#include <mutex>
#include <shared_mutex>
enum MessageType {
REGISTER = 1,
LOGIN = 2
};

struct Message {
MessageType type;
char username[50];
char password[50];
};

class Logger {
private:
std::fstream logfile;
std::shared_mutex mtx;
public:
Logger(const std::string& filename){
logfile.open(filename, std::fstream::in | std::fstream::out | std::fstream::app);
if(!logfile) throw std::runtime_error("Unable to open the log file!");
}

~Logger(){
    if(logfile.is_open()){
        logfile.close();
    }
}

void write_line(const std::string& log_line){
    std::unique_lock<std::shared_mutex> lock(mtx);
    logfile << log_line << std::endl;
}

std::string read_line(){
    std::shared_lock<std::shared_mutex> lock(mtx);
    std::string line;
    std::getline(logfile, line);
    return line;
}
};

const int PORT = 2000;
const char* db_file = "clients.db";
sqlite3* db;

bool register_user(const char* username, const char* password) {
const char* query = "INSERT INTO clients (username, password) VALUES (?, ?)";
sqlite3_stmt* stmt;
int rc;

std::string password_hash = BCrypt::generateHash(password);

rc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
if (rc != SQLITE_OK) {
    std::cerr << "Failed to prepare query: " << sqlite3_errmsg(db) << std::endl;
    return false;
}

rc = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
if (rc != SQLITE_OK) {
    std::cerr << "Failed to bind username: " << sqlite3_errmsg(db) << std::endl;
    return false;
}

rc = sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);
if (rc != SQLITE_OK) {
    std::cerr << "Failed to bind password: " << sqlite3_errmsg(db) << std::endl;
    return false;
}

rc = sqlite3_step(stmt);
if (rc != SQLITE_DONE) {
    std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
    sqlite3_finalize(stmt);
    return false;
}

sqlite3_finalize(stmt);

return true;
}

bool check_credentials(const char* username, const char* provided_password) {
const char* query = "SELECT password FROM clients WHERE username = ?";
sqlite3_stmt* stmt;
int rc;

rc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
if (rc != SQLITE_OK) {
    std::cerr << "Failed to prepare query: " << sqlite3_errmsg(db) << std::endl;
    return false;
}

rc = sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
if (rc != SQLITE_OK) {
    std::cerr << "Failed to bind username: " << sqlite3_errmsg(db) << std::endl;
    return false;
}

rc = sqlite3_step(stmt);
if (rc != SQLITE_ROW) {
    std::cerr << "Failed to execute query: " << sqlite3_errmsg(db) << std::endl;
    sqlite3_finalize(stmt);
    return false;
}

const unsigned char* password_hash = sqlite3_column_text(stmt, 0);
sqlite3_finalize(stmt);

// Compare password hash to provided password
bool password_matches = BCrypt::validatePassword(provided_password, (const char *)password_hash);

return password_matches;
}

bool process_login(int client_fd, const Message& msg) {
if (check_credentials(msg.username, msg.password)) {
send(client_fd, "Login successful\n", 17, 0);
return true;
} else {
send(client_fd, "Login failed\n", 13, 0);
return false;
}
}

bool process_registration(int client_fd, const Message& msg) {
if (register_user(msg.username, msg.password)) {
send(client_fd, "Registration successful\n", 24, 0);
return true;
} else {
send(client_fd, "Registration failed\n", 20, 0);
return false;
}
}

void process_request(int client_fd) {
Message msg;
int len = recv(client_fd, reinterpret_cast<char*>(&msg), sizeof(msg), 0);
if (len <= 0) {
std::cerr << "Failed to receive request" << std::endl;
return;
}

switch (msg.type) {
    case REGISTER:
        process_registration(client_fd, msg);
        break;
    case LOGIN:
        if (process_login(client_fd, msg)) {
            // Продолжайте обслуживание клиента после успешного входа в систему.
            // ...
        }
        break;
    default:
        std::cerr << "Unknown message type" << std::endl;
        break;
}
}

void run_server() {
     Logger logger("server_log.txt");
int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
if (listen_fd == -1) {
perror("socket");
return;
}

sockaddr_in server_addr;
memset(&server_addr, 0, sizeof(server_addr));
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(PORT);
server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

int opt = 1;
if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
    perror("setsockopt");
    return;
}

if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
    perror("bind");
    return;
}

if (listen(listen_fd, 10) == -1) {
    perror("listen");
    return;
}

std::cout << "Server started on port " << PORT << std::endl;

  while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_fd < 0) {
            perror("accept");
            return;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, clientIP, INET_ADDRSTRLEN);
        logger.write_line("Accepted connection from: " + std::string(clientIP));
        
        std::thread([client_fd, &logger]() {
            process_request(client_fd, logger); // передача logger как аргумента

#ifdef _WIN32
            closesocket(client_fd);
#else
            close(client_fd);
#endif
        }).detach();
    }

#ifdef _WIN32
    closesocket(listen_fd);
#else
    close(listen_fd);
#endif
}

bool process_registration(int client_fd, const Message& msg, Logger& logger) { // добавляем Logger в качестве аргумента

    if (register_user(msg.username, msg.password)) {
        send(client_fd, "Registration successful\n", 24, 0);
        logger.write_line(std::string(msg.username) + " registered successfully"); // добавляем запись в лог
        return true;
    } else {
        send(client_fd, "Registration failed\n", 20, 0);
        logger.write_line(std::string(msg.username) + " registration failed"); // добавляем запись в лог
        return false;
    }
}

bool process_login(int client_fd, const Message& msg, Logger& logger) { // добавляем Logger в качестве аргумента

    if (check_credentials(msg.username, msg.password)) {
        send(client_fd, "Login successful\n", 17, 0);
        logger.write_line(std::string(msg.username) + " login successful"); // добавляем запись в лог
        return true;
    } else {
        send(client_fd, "Login failed\n", 13, 0);
        logger.write_line(std::string(msg.username) + " login failed"); // добавляем запись в лог
        return false;
    }
}

void process_request(int client_fd, Logger& logger) { // добавляем Logger в качестве аргумента
    Message msg;
    int len = recv(client_fd, reinterpret_cast<char*>(&msg), sizeof(msg), 0);
    if (len <= 0) {
        std::cerr << "Failed to receive request" << std::endl;
        return;
    }

    switch (msg.type) {
        case REGISTER:
            process_registration(client_fd, msg, logger); // передается logger
            break;
        case LOGIN:
            process_login(client_fd, msg, logger); // передается logger
            break;
        default:
            std::cerr << "Unknown message type" << std::endl;
            break;
    }
}


void run_client() {
Logger logger("log.txt");
int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
if (sock_fd == -1) {
perror("Failed to create socket");
return;
}

sockaddr_in server_addr;
memset(&server_addr, 0, sizeof(server_addr));
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(PORT);

if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
    perror("inet_pton");
    return;
}

if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
    perror("Failed to connect to server");
    return;
}

char buffer[1024];
std::cout << "Enter username: ";
std::cin.getline(buffer, sizeof(buffer));
std::string username(buffer);

std::cout << "Enter password: ";
std::cin.getline(buffer, sizeof(buffer));
std::string password(buffer);

  while (true) {
char buffer[1024];
std::cout << "Enter message: ";
std::cin.getline(buffer, sizeof(buffer));

Message msg;
msg.type = LOGIN; // или REGISTER
strncpy(msg.username, username.c_str(), sizeof(msg.username) - 1);
strncpy(msg.password, password.c_str(), sizeof(msg.password) - 1);

ssize_t send_len = send(sock_fd, reinterpret_cast<char*>(&msg), sizeof(msg), 0);  // отправляем сообщение
if(send_len < 0) {
    perror("Failed to send message");
    return;
}

logger.write_line("Sent to server: " + std::string(buffer));

ssize_t recv_len = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);

if (recv_len <= 0) {
    std::cout << "Server has closed the connection" << std::endl;
    break;
}

buffer[recv_len] = '\0';
std::cout << "Server: " << buffer << std::endl;
logger.write_line("Received from server: " + std::string(buffer)); 
}

int main() {
#ifdef _WIN32
WSAData wsaData;
int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
if (iResult != 0) {
std::cerr << "WSAStartup failed: " << iResult << std::endl;
return 1;
}
#endif

int rc = sqlite3_open(db_file, &db);
if (rc != SQLITE_OK) {
    std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
    return 1;
}

std::thread server_thread(run_server);
std::this_thread::sleep_for(std::chrono::seconds(1));
std::thread client_thread(run_client);

server_thread.join();
client_thread.join();
#ifdef _WIN32
WSACleanup();
#endif

sqlite3_close(db);

return 0;
}