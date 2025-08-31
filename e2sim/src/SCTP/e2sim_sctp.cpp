/*****************************************************************************
#                                                                            *
# Copyright 2019 AT&T Intellectual Property                                  *
# Copyright 2019 Nokia                                                       *
#                                                                            *
# Licensed under the Apache License, Version 2.0 (the "License");            *
# you may not use this file except in compliance with the License.           *
# You may obtain a copy of the License at                                    *
#                                                                            *
#      http://www.apache.org/licenses/LICENSE-2.0                            *
#                                                                            *
# Unless required by applicable law or agreed to in writing, software        *
# distributed under the License is distributed on an "AS IS" BASIS,          *
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
# See the License for the specific language governing permissions and        *
# limitations under the License.                                             *
#                                                                            *
******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <unistd.h>		//for close()
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>	//for inet_ntop()
#include <assert.h>

#include "e2sim_sctp.hpp"
// #include "e2sim_defs.h"


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/sctp.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cerrno>

#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <poll.h>
#include <fcntl.h>

int sctp_start_server(const char *server_ip_str, const int server_port)
{
  if(server_port < 1 || server_port > 65535) {
      LOG_E("Invalid port number (%d). Valid values are between 1 and 65535.\n", server_port);
      exit(1);
  }

  int server_fd, af;
  struct sockaddr* server_addr;
  size_t addr_len;

  struct sockaddr_in  server4_addr;
  memset(&server4_addr, 0, sizeof(struct sockaddr_in));

  struct sockaddr_in6 server6_addr;
  memset(&server6_addr, 0, sizeof(struct sockaddr_in6));

  if(inet_pton(AF_INET, server_ip_str, &server4_addr.sin_addr) == 1)
  {
    server4_addr.sin_family = AF_INET;
    server4_addr.sin_port   = htons(server_port);

    server_addr = (struct sockaddr*)&server4_addr;
    af          = AF_INET;
    addr_len    = sizeof(server4_addr);
  }
  else if(inet_pton(AF_INET6, server_ip_str, &server6_addr.sin6_addr) == 1)
  {
    server6_addr.sin6_family = AF_INET6;
    server6_addr.sin6_port   = htons(server_port);

    server_addr = (struct sockaddr*)&server6_addr;
    af          = AF_INET6;
    addr_len    = sizeof(server6_addr);
  }
  else {
    perror("inet_pton()");
    exit(1);
  }

  if((server_fd = socket(af, SOCK_STREAM, IPPROTO_SCTP)) == -1) {
    perror("socket");
    exit(1);
  }

  //set send_buffer
  // int sendbuff = 10000;
  // socklen_t optlen = sizeof(sendbuff);
  // if(getsockopt(server_fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, &optlen) == -1) {
  //   perror("getsockopt send");
  //   exit(1);
  // }
  // else
  //   LOG_D("[SCTP] send buffer size = %d\n", sendbuff);


  if(bind(server_fd, server_addr, addr_len) == -1) {
    perror("bind");
    exit(1);
  }

  if(listen(server_fd, SERVER_LISTEN_QUEUE_SIZE) != 0) {
    perror("listen");
    exit(1);
  }

  assert(server_fd != 0);

  LOG_I("[SCTP] Server started on %s:%d", server_ip_str, server_port);

  return server_fd;
}

// Stampa gli eventi SCTP dal socket fd (non blocca se non ci sono eventi)
void sctp_print_events(int fd)
{
    char buf[1024];
    struct iovec iov;
    struct msghdr msg;
    ssize_t n;

    iov.iov_base = buf;
    iov.iov_len  = sizeof(buf);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    // Legge con MSG_DONTWAIT: non blocca
    n = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (n <= 0) {
        return; // nessun evento
    }

    if (msg.msg_flags & MSG_NOTIFICATION) {
        union sctp_notification *snp = (union sctp_notification*)buf;
        switch (snp->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE: {
            struct sctp_assoc_change *sac = &snp->sn_assoc_change;
            const char* state_str = "UNKNOWN";
            switch (sac->sac_state) {
                case SCTP_COMM_UP:         state_str = "COMM_UP"; break;
                case SCTP_COMM_LOST:       state_str = "COMM_LOST"; break;
                case SCTP_RESTART:         state_str = "RESTART"; break;
                case SCTP_SHUTDOWN_COMP:   state_str = "SHUTDOWN_COMPLETE"; break;
                case SCTP_CANT_STR_ASSOC:  state_str = "CANT_START_ASSOC"; break;
            }
            fprintf(stderr, "[SCTP_EVENT] ASSOC_CHANGE: %s (assoc=0x%x)\n",
                    state_str, sac->sac_assoc_id);
            break;
        }
        case SCTP_SHUTDOWN_EVENT: {
            struct sctp_shutdown_event *sse = &snp->sn_shutdown_event;
            fprintf(stderr, "[SCTP_EVENT] SHUTDOWN (assoc=0x%x)\n", sse->sse_assoc_id);
            break;
        }
        case SCTP_SEND_FAILED_EVENT: {
            fprintf(stderr, "[SCTP_EVENT] SEND_FAILED\n");
            break;
        }
        case SCTP_ADAPTATION_INDICATION: {
            fprintf(stderr, "[SCTP_EVENT] ADAPTATION_INDICATION\n");
            break;
        }
        case SCTP_PARTIAL_DELIVERY_EVENT: {
            fprintf(stderr, "[SCTP_EVENT] PARTIAL_DELIVERY\n");
            break;
        }
        case SCTP_REMOTE_ERROR: {
            fprintf(stderr, "[SCTP_EVENT] REMOTE_ERROR\n");
            break;
        }
        default:
            fprintf(stderr, "[SCTP_EVENT] Unknown type %u\n", snp->sn_header.sn_type);
            break;
        }
    }
}

static void enable_sctp_events(int fd) {
    struct sctp_event_subscribe ev = {};
    ev.sctp_data_io_event = 1;
    ev.sctp_association_event = 1;
    ev.sctp_shutdown_event = 1;
    ev.sctp_send_failure_event = 1;
    ev.sctp_partial_delivery_event = 1;
    ev.sctp_adaptation_layer_event = 1;
    ev.sctp_address_event = 1;
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &ev, sizeof(ev));
}

static int set_nonblock(int fd, bool on) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (on) fl |= O_NONBLOCK;
    else    fl &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, fl);
}

int sctp_start_client(const char *server_ip_str, const int server_port)
{
    int family = AF_UNSPEC;
    sockaddr_in  peer4{}; sockaddr_in6 peer6{};
    sockaddr *peer = nullptr; socklen_t peer_len = 0;

    if (inet_pton(AF_INET, server_ip_str, &peer4.sin_addr) == 1) {
        family = AF_INET; peer4.sin_family = AF_INET; peer4.sin_port = htons(server_port);
        peer = (sockaddr*)&peer4; peer_len = sizeof(peer4);
    } else {
        fprintf(stderr, "[SCTP] inet_pton failed for '%s'\n", server_ip_str);
        return -1;
    }

    int fd = socket(family, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) { perror("[SCTP] socket"); return -1; }

    // Parametri iniziali (facoltativi)
    sctp_initmsg init{}; init.sinit_num_ostreams = 2; init.sinit_max_instreams = 2; init.sinit_max_attempts = 4;
    (void)setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init));

    // Eventi per debug (facoltativo ma consigliato)
    enable_sctp_events(fd);

    // Rendi NON-blocking, così copriamo tutti i casi (anche se qualche altro punto del codice imposta O_NONBLOCK)
    if (set_nonblock(fd, true) < 0) { perror("[SCTP] fcntl(O_NONBLOCK)"); close(fd); return -1; }

    fprintf(stderr, "[SCTP] Connecting to %s:%d ... ", server_ip_str, server_port);
    int rc = connect(fd, peer, peer_len);
    if (rc == 0) {
        fprintf(stderr, "OK (immediato)\n");
        return fd;
    }

    if (rc < 0 && errno != EINPROGRESS && errno != EINTR) {
        fprintf(stderr, "FAILED (errno=%d: %s)\n", errno, strerror(errno));
        close(fd);
        return -1;
    }

    // Attendi il completamento della connect
    struct pollfd p{ .fd = fd, .events = POLLOUT, .revents = 0 };
    rc = poll(&p, 1, 50000); // timeout 50s
    if (rc == 0) {
        fprintf(stderr, "FAILED (timeout 50000 ms)\n");
        close(fd);
        return -1;
    }
    if (rc < 0) {
        fprintf(stderr, "FAILED (poll errno=%d: %s)\n", errno, strerror(errno));
        close(fd);
        return -1;
    }

    // Verifica l’esito reale
    int soerr = 0; socklen_t sl = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0) {
        perror("[SCTP] getsockopt(SO_ERROR)"); close(fd); return -1;
    }
    if (soerr != 0) {
        fprintf(stderr, "FAILED (SO_ERROR=%d: %s)\n", soerr, strerror(soerr));
        close(fd);
        return -1;
    }

    fprintf(stderr, "OK\n");

    // (opzionale) torna blocking per il resto della logica
    (void)set_nonblock(fd, false);

    return fd;
}

int sctp_accept_connection(const char *server_ip_str, const int server_fd)
{
  LOG_I("[SCTP] Waiting for new connection...");

  struct sockaddr client_addr;
  socklen_t       client_addr_size;
  int             client_fd;

  //Blocking call
  client_fd = accept(server_fd, &client_addr, &client_addr_size);
  fprintf(stderr, "client fd is %d\n", client_fd);
  if(client_fd == -1){
    perror("accept()");
    close(client_fd);
    exit(1);
  }

  //Retrieve client IP_ADDR
  char client_ip6_addr[INET6_ADDRSTRLEN], client_ip4_addr[INET_ADDRSTRLEN];
  if(strchr(server_ip_str, ':') != NULL) //IPv6
  {
    struct sockaddr_in6* client_ipv6 = (struct sockaddr_in6*)&client_addr;
    inet_ntop(AF_INET6, &(client_ipv6->sin6_addr), client_ip6_addr, INET6_ADDRSTRLEN);
    LOG_I("[SCTP] New client connected from %s", client_ip6_addr);
  }
  else {
    struct sockaddr_in* client_ipv4 = (struct sockaddr_in*)&client_addr;
    inet_ntop(AF_INET, &(client_ipv4->sin_addr), client_ip4_addr, INET_ADDRSTRLEN);
    LOG_I("[SCTP] New client connected from %s", client_ip4_addr);
  }

  return client_fd;
}

int sctp_send_data(int &socket_fd, sctp_buffer_t &data)
{
    fprintf(stderr,"in sctp send data func\n");
    fprintf(stderr,"data.len is %d\n", data.len);

    if(socket_fd < 0) {
        fprintf(stderr,"[SCTP] Invalid socket\n");
        return -1;
    }

    // PPID per E2AP = 60 (decimale)
    uint32_t ppid = htonl(60);

    int sent_len = sctp_sendmsg(
        socket_fd,
        data.buffer,   // puntatore ai byte
        data.len,      // lunghezza
        NULL, 0,       // dest addr = NULL perché il socket è già connesso
        ppid,          // Payload Protocol Identifier
        0,             // flags
        0,             // stream = 0
        0,             // timetolive
        0              // context
    );

    fprintf(stderr,"after getting sent_len: %d\n", sent_len);

    if(sent_len == -1) {
        perror("[SCTP] sctp_send_data");
        return -1;
    }

    return sent_len;
}

int sctp_send_data_X2AP(int &socket_fd, sctp_buffer_t &data)
{
  int sent_len = sctp_sendmsg(socket_fd, (void*)(&(data.buffer[0])), data.len,
                  NULL, 0, (uint32_t) X2AP_PPID, 0, 0, 0, 0);

  if(sent_len == -1) {
    perror("[SCTP] sctp_send_data");
    exit(1);
  }
  return sent_len;
}

/*
Receive data from SCTP socket
Outcome of recv()
-1: exit the program
0: close the connection
+: new data
*/
int sctp_receive_data(int &socket_fd, sctp_buffer_t &data)
{
  //clear out the data before receiving
  memset(data.buffer, 0, sizeof(data.buffer));
  data.len = 0;

  //receive data from the socket
  int recv_len = recv(socket_fd, &(data.buffer), sizeof(data.buffer), 0);
  
  if(recv_len == -1)
  {
    perror("[SCTP] recv len -1");
    exit(1);
  }
  else if (recv_len == 0)
  {
    LOG_I("[SCTP] Connection closed by remote peer");
    if(close(socket_fd) == -1)
    {
      perror("[SCTP] close");
    }
    return -1;
  }

  data.len = recv_len;

  return recv_len;
}
