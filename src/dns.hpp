#pragma once

#include <cstdint>

#include <functional>
#include <memory>
#include <string>
#include <map>
#include <vector>

#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace lynxdns
{
    struct alignas(1) message_header
    {
        uint16_t id;
        //     4.1.1. Header section format
        //
        //     The header contains the following fields:
        //
        //                                    1  1  1  1  1  1
        //      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        uint16_t flag;

        uint16_t qd_count;
        uint16_t an_count;
        uint16_t ns_count;
        uint16_t ar_count;

        message_header(const message_header&) = default;
        message_header(const char* msg_in);
    };

    class dns_name : public std::vector<std::string>
    {
    public:
        dns_name() = default;
        dns_name(const std::string& str);
        operator std::string() const
        {
            std::string r;
            for (const auto& v : static_cast<std::vector<std::string>>(*this))
            {
                r += v.length() == 0 ? v : v + ".";
            }
            return r;
        }
    };

    struct message_question
    {
        dns_name qname;
        uint16_t qtype;
        uint16_t qclass;
    };

    struct alignas(1) resource_record
    {
        enum : uint16_t
        {
            TYPE_A     = 1,
            TYPE_NS    = 2,
            TYPE_CNAME = 4,
            TYPE_TXT   = 16,
            TYPE_AAAA  = 28
        } type;
        uint16_t rrclass;
        uint32_t ttl;
        uint16_t rdlength;
    };
    struct alignas(1) resource_record_a : resource_record
    {
        uint32_t address;
    };
    struct alignas(1) resource_record_aaaa : resource_record
    {
        uint8_t address[16];
    };
    struct alignas(1) resource_record_cname : resource_record
    {
        dns_name name;
    };
    struct alignas(1) resource_record_ns : resource_record
    {
        dns_name name;
    };

    constexpr static resource_record_a    default_a_answer    = { resource_record::TYPE_A, 1, 17800, 4, 0x771d1d1d };
    constexpr static resource_record_aaaa default_aaaa_answer = { resource_record::TYPE_AAAA,
                                                                  1,
                                                                  17800,
                                                                  16,
                                                                  { 0x24, 0x02, 0x0e, 0x00 } };

    class dns_query
    {
    private:
        std::unique_ptr<char[]> _message_in;
        size_t                  _message_length;

        message_header                _header;
        std::vector<message_question> _question_list;

    public:
        dns_query(std::unique_ptr<char[]> msg_in, size_t msg_len);
        ~dns_query();

        const std::vector<message_question>& get_question_list();
    };

    class dns_response
    {
    public:
        dns_response(
            const std::vector<message_question>&                   question_list,
            std::multimap<std::string, resource_record>& cache_map);
        ~dns_response() = default;
    };

    template <typename Tpeer>
    class dns_server
    {
        
    public:
        constexpr static auto DNS_UDP_MSG_LEN_RESTRICTION = 512;
        constexpr static auto is_authority                = false;

        typedef std::unique_ptr<char[]>                                                          buffer_pointer;
        typedef std::function<std::tuple<Tpeer, size_t, buffer_pointer>(buffer_pointer, size_t)> recv_function;
        typedef std::function<size_t(buffer_pointer, size_t, Tpeer)>                             send_function;

    private:
        std::multimap<std::string, resource_record> _cache_map;

        recv_function _recv;
        send_function _send;

    public:
        dns_server(recv_function recv, send_function send)
            : _recv(recv)
            , _send(send)
        {
            Tpeer  recv_peer;
            size_t recv_size;
            auto   recv_buf = std::make_unique<char[]>(DNS_UDP_MSG_LEN_RESTRICTION);

            std::tie(recv_peer, recv_size, recv_buf) = _recv(std::move(recv_buf), DNS_UDP_MSG_LEN_RESTRICTION);
            dns_query    query(std::move(recv_buf), recv_size);
            dns_response dns_response(query.get_question_list(), _cache_map);
        }
        ~dns_server() = default;
    };
} // namespace lynxdns
