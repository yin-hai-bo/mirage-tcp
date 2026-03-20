#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "mirage_tcp/mirage_tcp.h"

namespace {

struct DemoContext {
    std::vector<std::uint8_t> last_packet;
    bool handshake_completed;
};

void on_downstream_ip_packet_generated(void* user_data, const void* ip_packet, std::size_t ip_packet_size) {
    DemoContext* context = static_cast<DemoContext*>(user_data);
    const std::uint8_t* bytes = static_cast<const std::uint8_t*>(ip_packet);
    context->last_packet.assign(bytes, bytes + static_cast<std::ptrdiff_t>(ip_packet_size));
}

void on_tcp_handshake_completed(void* user_data, const mirage_tcp::ConnectionInfo&) {
    DemoContext* context = static_cast<DemoContext*>(user_data);
    context->handshake_completed = true;
}

void on_tcp_connection_reset(void*, const mirage_tcp::ConnectionInfo&) {
    std::cout << "flow reset by MirageTcp" << std::endl;
}

}  // namespace

int main() {
    DemoContext context;
    context.handshake_completed = false;

    mirage_tcp::MirageTcpCallbacks callbacks;
    callbacks.user_data = &context;
    callbacks.on_downstream_ip_packet_generated = on_downstream_ip_packet_generated;
    callbacks.on_tcp_handshake_completed = on_tcp_handshake_completed;
    callbacks.on_tcp_connection_reset = on_tcp_connection_reset;

    mirage_tcp::MirageTcp mirage_tcp(callbacks);
    std::cout << "MirageTcp host is ready for virtual-NIC packet injection." << std::endl;
    std::cout << "Integrate handle_incoming_ip_packet(...) with your WinTun receive loop." << std::endl;
    std::cout << "Include mirage_tcp/error_code.h only when you need to inspect specific ErrorCode values." << std::endl;
    std::cout << "Use send_downstream_tcp_payload(...) after handshake completion to fake server data." << std::endl;
    std::cout << "Use close_flow(...) when you want MirageTcp to locally terminate the flow." << std::endl;
    return 0;
}
