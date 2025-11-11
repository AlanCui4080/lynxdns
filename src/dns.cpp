#include <bit>
#include <sstream>
#include <stdexcept>

#include "dns.hpp"
#include "utility.hpp"

using namespace lynxdns;

dns_name::dns_name(const std::string& str)
{
    auto        iss = std::istringstream(str);
    std::string token;

    while (std::getline(iss, token, '.'))
        ;
}

message_header::message_header(const char* msg_in)
    : message_header(*reinterpret_cast<const message_header*>(msg_in))
{
    this->id       = utility::ntoh(this->id);
    this->flag     = utility::ntoh(this->flag);
    this->qd_count = utility::ntoh(this->qd_count);
    this->an_count = utility::ntoh(this->an_count);
    this->ns_count = utility::ntoh(this->ns_count);
    this->ar_count = utility::ntoh(this->ar_count);
}

dns_query::dns_query(std::unique_ptr<char[]> msg_in, size_t msg_len)
    : _message_in(std::move(msg_in))
    , _message_length(msg_len)
    , _header(_message_in.get())
{
    // 4.1. Format
    //
    // All communications inside of the domain protocol are carried in a single
    // format called a message.  The top level format of message is divided
    // into 5 sections (some of which are empty in certain cases) shown below:
    //
    //     +---------------------+
    //     |        Header       |
    //     +---------------------+
    //     |       Question      | the question for the name server
    //     +---------------------+
    //     |        Answer       | RRs answering the question
    //     +---------------------+
    //     |      Authority      | RRs pointing toward an authority
    //     +---------------------+
    //     |      Additional     | RRs holding additional information
    //     +---------------------+
    //
    // The header section is always present.  The header includes fields that
    // specify which of the remaining sections are present, and also specify
    // whether the message is a query or a response, a standard query or some
    // other opcode, etc.
    //
    // The names of the sections after the header are derived from their use in
    // standard queries.  The question section contains fields that describe a
    // question to a name server.  These fields are a query type (QTYPE), a
    // query class (QCLASS), and a query domain name (QNAME).  The last three
    // sections have the same format: a possibly empty list of concatenated
    // resource records (RRs).  The answer section contains RRs that answer the
    // question; the authority section contains RRs that point toward an
    // authoritative name server; the additional records section contains RRs
    // which relate to the query, but are not strictly answers for the
    // question.
    spdlog::trace(
        "dns_query: message binary: {}", spdlog::to_hex(_message_in.get(), _message_in.get() + _message_length));
    spdlog::debug("dns_query: message id: {}, flag: 0x{:X}, size: {}", _header.id, _header.flag, _message_length);
    if ((_header.flag & 0x8000) >> 15 != 0)
    {
        spdlog::error("dns_query: message is not a query");
        throw std::runtime_error("dns_query: message is not a query");
    }
    spdlog::debug(
        "dns_query: opcode: {}, recursion required: {}, truncated: {}",
        (_header.flag & 0x7800) >> 11,
        (_header.flag & 0x0100) >> 8,
        (_header.flag & 0x0200) >> 9);
    spdlog::debug("dns_query: this query has {} question(s)", _header.qd_count);
    spdlog::debug("dns_query: this query has {} answer(s)", _header.an_count);
    spdlog::debug("dns_query: this query has {} authorit(y/ies)", _header.ns_count);
    spdlog::debug("dns_query: this query has {} addition(s)", _header.ar_count);

    static_assert(sizeof(message_header) == 12);
    size_t message_ptr = sizeof(message_header);

    // 4.1.2. Question section format
    //
    // The question section is used to carry the "question" in most queries,
    // i.e., the parameters that define what is being asked.  The section
    // contains QDCOUNT (usually 1) entries, each of the following format:
    //
    //                                   1  1  1  1  1  1
    //     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                                               |
    //     /                     QNAME                     /
    //     /                                               /
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                     QTYPE                     |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                     QCLASS                    |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //
    // where:
    //
    // QNAME           a domain name represented as a sequence of labels, where
    //                 each label consists of a length octet followed by that
    //                 number of octets.  The domain name terminates with the
    //                 zero length octet for the null label of the root.  Note
    //                 that this field may be an odd number of octets; no
    //                 padding is used.
    //
    // QTYPE           a two octet code which specifies the type of the query.
    //                 The values for this field include all codes valid for a
    //                 TYPE field, together with some more general codes which
    //                 can match more than one type of RR.
    //
    // QCLASS          a two octet code that specifies the class of the query.
    //                 For example, the QCLASS field is IN for the Internet.

    for (size_t i = 0; i < _header.qd_count; i++)
    {
        message_question question;
        size_t           label_length;
        do
        {
            label_length = _message_in[message_ptr];
            if (label_length > 63)
            {
                // 4.1.4. Message compression

                // well, there is no DNS server/client support multiple questions including Google and BIND9
                // so even qd_count will not greater that 1, message copression is almost impossible to shown here
                spdlog::error("dns_query: this question has message copression");
                throw std::runtime_error("dns_query: message has copression");
            }
            question.qname.emplace_back(&_message_in[message_ptr + 1], label_length); // construct std::string in place

            message_ptr += label_length + 1;
        } while (label_length != 0);

        // C11, 6.3.2
        // A pointer to an object type may be converted to a pointer to a different object type.
        // If the resulting pointer is not correctly aligned for the referenced type, the behavior is undefined.
        question.qtype  = utility::ntoh<uint16_t>(_message_in[message_ptr + 1] << 8 | _message_in[message_ptr]);
        question.qclass = utility::ntoh<uint16_t>(_message_in[message_ptr + 3] << 8 | _message_in[message_ptr + 2]);

        spdlog::debug(
            "dns_query: question {}: label: {}, qtype {}, qclass {}",
            i,
            question.qname,
            question.qtype,
            question.qclass);

        _question_list.emplace_back(std::move(question));
        message_ptr += 4;
    }

    if (_header.an_count > 0)
    {
        spdlog::warn("dns_query: this query has answer(s) in itself, ignored.");
    }

    if (_header.ns_count > 0)
    {
        spdlog::warn("dns_query: this query has authorit(y/ies) in itself, ignored.");
    }

    if (_header.ar_count > 0)
    {
        spdlog::warn("dns_query: this query has addition(s) in itself, ignored.");
    }

    for (const auto& v : _question_list)
    {
        spdlog::info(
            "dns_query: id {} question: {}, type: {}, class: {}",
            _header.id,
            static_cast<std::string>(v.qname),
            v.qtype,
            v.qclass);
    }
}

dns_query::~dns_query()
{
}

const std::vector<message_question>& dns_query::get_question_list()
{
    return _question_list;
}

dns_response::dns_response(
    const std::vector<message_question>&         question_list,
    std::multimap<std::string, resource_record>& cache_map)
{
    for (const auto& v : question_list)
    {
        cache_map.find(static_cast<std::string>(v.qname));
    }
}