#include <cstring>
#include <memory>
#include <stdexcept>

#include <netinet/in.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "dns.hpp"

int main()
{
    spdlog::set_level(spdlog::level::trace);

    int socket_fd;
    if ((socket_fd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
        spdlog::error("socket(): {}", strerror(errno));

    sockaddr_in6 servaddr;
    servaddr.sin6_family   = AF_INET6;
    servaddr.sin6_port     = htons(5443);
    servaddr.sin6_flowinfo = 0;
    servaddr.sin6_scope_id = 0;
    servaddr.sin6_addr     = IN6ADDR_ANY_INIT;

    int result;
    if ((result = bind(socket_fd, (sockaddr*)&servaddr, sizeof(servaddr))) < 0)
        spdlog::error("bind(): {}", strerror(errno));

    lynxdns::dns_server<sockaddr_in6>(
        [&](std::unique_ptr<char[]> recvbuf, size_t size) -> std::tuple<sockaddr_in6, size_t, std::unique_ptr<char[]>> {
            sockaddr_in6 peeraddr;
            socklen_t    peerlen = sizeof(peeraddr);
            int          n;

            if ((n = recvfrom(socket_fd, recvbuf.get(), size, 0, (sockaddr*)&peeraddr, &peerlen)) < 0)
            {
                spdlog::error("recvfrom(): {}", strerror(errno));
                throw std::system_error(n, std::system_category(), "recvfrom():");
            }

            return std::make_tuple(peeraddr, static_cast<size_t>(n), std::move(recvbuf));
        },
        [&](std::unique_ptr<char[]> sendbuf, size_t size, sockaddr_in6 peeraddr) -> size_t {
            int n;
            if ((n = sendto(socket_fd, sendbuf.get(), size, 0, (sockaddr*)&peeraddr, sizeof(peeraddr))) < 0)
            {
                spdlog::error("sendto(): {}", strerror(errno));
                throw std::system_error(n, std::system_category(), "sendto():");
            }

            return static_cast<size_t>(n);
        });

    return 0;
}