#include <mirage_tcp/error_code.h>
#include <mirage_tcp/mirage_tcp.h>

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <linux/if_tun.h>

namespace {

volatile sig_atomic_t g_should_stop = 0;

void on_signal(int) {
    g_should_stop = 1;
}

std::string get_env_or_default(const char* name, const char* default_value) {
    const char* value = std::getenv(name);
    if (value == NULL || value[0] == '\0') {
        return std::string(default_value);
    }
    return std::string(value);
}

std::string build_http_response() {
    const std::string body = get_env_or_default(
        "MIRAGE_TCP_LIVE_PROBE_BODY",
        "MirageTCP live probe reached the local terminator.\n");
    std::ostringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: text/plain\r\n";
    response << "Content-Length: " << body.size() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;
    return response.str();
}

void run_command(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (std::size_t index = 0; index < args.size(); ++index) {
        argv.push_back(const_cast<char*>(args[index].c_str()));
    }
    argv.push_back(NULL);

    const pid_t child_pid = fork();
    if (child_pid < 0) {
        throw std::runtime_error(std::string("fork() failed: ") + std::strerror(errno));
    }

    if (child_pid == 0) {
        execvp(argv[0], &argv[0]);
        std::perror("execvp");
        _exit(127);
    }

    int status = 0;
    if (waitpid(child_pid, &status, 0) < 0) {
        throw std::runtime_error(std::string("waitpid() failed: ") + std::strerror(errno));
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::ostringstream message;
        message << "command failed:";
        for (std::size_t index = 0; index < args.size(); ++index) {
            message << ' ' << args[index];
        }
        throw std::runtime_error(message.str());
    }
}

void configure_tun_device(const std::string& tun_name) {
    const std::string local_ip = get_env_or_default("MIRAGE_TCP_LIVE_PROBE_LOCAL_IP", "10.200.0.1/24");
    const std::string target_ip = get_env_or_default("MIRAGE_TCP_LIVE_PROBE_TARGET_IP", "10.200.0.2/32");

    run_command(std::vector<std::string>{"ip", "addr", "replace", local_ip, "dev", tun_name});
    run_command(std::vector<std::string>{"ip", "link", "set", tun_name, "up"});
    run_command(std::vector<std::string>{"ip", "route", "replace", target_ip, "dev", tun_name});

    std::cout << "configured " << tun_name << std::endl;
    std::cout << "local address: " << local_ip << std::endl;
    std::cout << "intercept target: " << target_ip << std::endl;
}

int open_tun_device(const std::string& requested_name, std::string& actual_name) {
    const int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return -1;
    }

    ifreq interface_request;
    std::memset(&interface_request, 0, sizeof(interface_request));
    interface_request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    std::snprintf(interface_request.ifr_name, IFNAMSIZ, "%s", requested_name.c_str());

    if (ioctl(fd, TUNSETIFF, &interface_request) < 0) {
        const int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    actual_name = interface_request.ifr_name;
    return fd;
}

bool write_full(int fd, const void* buffer, std::size_t size) {
    const char* bytes = static_cast<const char*>(buffer);
    std::size_t offset = 0;
    while (offset < size) {
        const ssize_t written = write(fd, bytes + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

std::string format_connection(const mirage_tcp::ConnectionInfo& connection_info) {
    char client_ip[INET_ADDRSTRLEN];
    char server_ip[INET_ADDRSTRLEN];
    const char* client_text = inet_ntop(AF_INET, &connection_info.client_ip.ipv4, client_ip, sizeof(client_ip));
    const char* server_text = inet_ntop(AF_INET, &connection_info.server_ip.ipv4, server_ip, sizeof(server_ip));
    std::ostringstream stream;
    stream << (client_text ? client_text : "<invalid>")
           << ":" << connection_info.client_port
           << " -> "
           << (server_text ? server_text : "<invalid>")
           << ":" << connection_info.server_port;
    return stream.str();
}

class LiveProbe {
public:
    explicit LiveProbe(int tun_fd)
        : tun_fd_(tun_fd),
          http_response_(build_http_response()),
          mirage_tcp_(build_callbacks(this)) {}

    void run() {
        std::cout << "MirageTCP live probe is running on TUN device." << std::endl;
        while (!g_should_stop) {
            const ssize_t read_size = read(tun_fd_, packet_buffer_, sizeof(packet_buffer_));
            if (read_size < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("read(TUN) failed: ") + std::strerror(errno));
            }

            const mirage_tcp::error_code_t result =
                mirage_tcp_.handle_incoming_ip_packet(packet_buffer_, static_cast<std::size_t>(read_size));
            if (result != mirage_tcp::ErrorCode::Ok &&
                result != mirage_tcp::ErrorCode::IsNotTcp &&
                result != mirage_tcp::ErrorCode::Unsupported)
            {
                std::cerr << "MirageTcp rejected packet with error code " << result << std::endl;
            }
        }
    }

private:
    static mirage_tcp::MirageTcpCallbacks build_callbacks(LiveProbe* self) {
        mirage_tcp::MirageTcpCallbacks callbacks;
        callbacks.user_data = self;
        callbacks.on_downstream_ip_packet_generated = &LiveProbe::on_downstream_ip_packet_generated;
        callbacks.on_tcp_handshake_completed = &LiveProbe::on_tcp_handshake_completed;
        callbacks.on_tcp_payload_received = &LiveProbe::on_tcp_payload_received;
        callbacks.on_tcp_connection_closed = &LiveProbe::on_tcp_connection_closed;
        callbacks.on_tcp_connection_reset = &LiveProbe::on_tcp_connection_reset;
        return callbacks;
    }

    static void on_downstream_ip_packet_generated(void* user_data, const void* ip_packet, std::size_t ip_packet_size) {
        LiveProbe* self = static_cast<LiveProbe*>(user_data);
        if (!write_full(self->tun_fd_, ip_packet, ip_packet_size)) {
            std::cerr << "failed to write downstream packet to TUN: " << std::strerror(errno) << std::endl;
            g_should_stop = 1;
        }
    }

    static void on_tcp_handshake_completed(void*, const mirage_tcp::ConnectionInfo& connection_info) {
        std::cout << "handshake completed: " << format_connection(connection_info) << std::endl;
    }

    static void on_tcp_payload_received(
        void* user_data,
        const mirage_tcp::ConnectionInfo& connection_info,
        const void*,
        std::size_t payload_size)
    {
        LiveProbe* self = static_cast<LiveProbe*>(user_data);
        std::cout << "payload received: " << format_connection(connection_info)
                  << ", bytes=" << payload_size << std::endl;

        const mirage_tcp::error_code_t send_result = self->mirage_tcp_.send_downstream_tcp_payload(
            connection_info,
            self->http_response_.data(),
            self->http_response_.size());
        if (send_result != mirage_tcp::ErrorCode::Ok) {
            std::cerr << "send_downstream_tcp_payload failed: " << send_result << std::endl;
            return;
        }

        const mirage_tcp::error_code_t close_result = self->mirage_tcp_.close_flow(connection_info);
        if (close_result != mirage_tcp::ErrorCode::Ok) {
            std::cerr << "close_flow failed: " << close_result << std::endl;
        }
    }

    static void on_tcp_connection_closed(void*, const mirage_tcp::ConnectionInfo& connection_info) {
        std::cout << "connection closed: " << format_connection(connection_info) << std::endl;
    }

    static void on_tcp_connection_reset(void*, const mirage_tcp::ConnectionInfo& connection_info) {
        std::cout << "connection reset: " << format_connection(connection_info) << std::endl;
    }

    int tun_fd_;
    std::string http_response_;
    mirage_tcp::MirageTcp mirage_tcp_;
    alignas(8) char packet_buffer_[65535];
};

}  // namespace

int main() {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    const std::string requested_tun_name = get_env_or_default("MIRAGE_TCP_LIVE_PROBE_TUN", "mtcp0");
    std::string actual_tun_name;
    const int tun_fd = open_tun_device(requested_tun_name, actual_tun_name);
    if (tun_fd < 0) {
        std::cerr << "failed to open TUN device: " << std::strerror(errno) << std::endl;
        return 1;
    }

    try {
        std::cout << "created TUN device " << actual_tun_name << std::endl;
        configure_tun_device(actual_tun_name);
        std::cout << "test with: curl --max-time 3 http://10.200.0.2/" << std::endl;
        LiveProbe probe(tun_fd);
        probe.run();
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        close(tun_fd);
        return 1;
    }

    close(tun_fd);
    return 0;
}
