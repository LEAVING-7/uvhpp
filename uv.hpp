#pragma once
#include <uv.h>

#include <bit>      // std::bit_cast
#include <cassert>  // assert
#include <chrono>   // std::chrono::*

namespace uv {
inline auto Version() noexcept -> unsigned int { return uv_version(); }
inline auto VersionStr() noexcept -> char const* { return uv_version_string(); }

class Error {
public:
  Error() noexcept = default;
  Error(int err) noexcept : mRaw(static_cast<uv_errno_t>(err)) {}
  Error(uv_errno_t err) noexcept : mRaw(err) {}

  operator bool() const noexcept { return mRaw != 0; }
  auto Str() const noexcept -> char const* { return uv_strerror(Raw()); }
  auto Str(char* buf, std::size_t buflen) const noexcept -> char* { return uv_strerror_r(Raw(), buf, buflen); }
  auto Name() const noexcept -> char const* { return uv_err_name(Raw()); }
  auto Name(char* buf, std::size_t buflen) const noexcept -> char* { return uv_err_name_r(Raw(), buf, buflen); }
  auto TranslateSysError() const noexcept -> Error { return uv_translate_sys_error(Raw()); }

  auto Val() const noexcept -> int { return mRaw; }
  auto Raw() const noexcept -> uv_errno_t { return mRaw; }

private:
  uv_errno_t mRaw{};
};

class Loop {
public:
  Loop() noexcept = default;

  auto Init(void* userdata = nullptr) noexcept -> Error
  {
    SetData(userdata);
    return uv_loop_init(Raw());
  }
  auto Init(uv_loop_option option) noexcept -> Error { return uv_loop_configure(Raw(), option); }
  auto Close() noexcept -> Error { return uv_loop_close(Raw()); }
  static auto Default() noexcept -> Loop* { return std::bit_cast<Loop*>(uv_default_loop()); }
  auto Run() noexcept -> Error { return uv_run(Raw(), UV_RUN_DEFAULT); }
  auto Alive() const noexcept -> bool { return uv_loop_alive(Raw()) == 0 ? false : true; }
  auto Stop() noexcept -> void { uv_stop(Raw()); }
  static auto Size() noexcept -> std::size_t { return uv_loop_size(); }
  auto BackendFd() const noexcept -> int { return uv_backend_fd(Raw()); }
  // -1 for no timeout, in milliseconds
  auto BackendTimeout() const noexcept -> int { return uv_backend_timeout(Raw()); }
  // in milliseconds
  auto Now() const noexcept -> std::chrono::duration<std::uint64_t, std::milli>
  {
    return std::chrono::duration<std::uint64_t, std::milli>(uv_now(Raw()));
  }
  auto UpdateTime() noexcept -> void { uv_update_time(Raw()); }
  auto Walk(uv_walk_cb walk_cb, void* arg) noexcept -> void { return uv_walk(Raw(), walk_cb, arg); }
  auto Fork() noexcept -> Error { return uv_loop_fork(Raw()); }

  auto GetData() const noexcept -> void* { return uv_loop_get_data(Raw()); }
  auto SetData(void* data) noexcept -> void { uv_loop_set_data(Raw(), data); }

  auto Raw() noexcept -> uv_loop_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_loop_t const* { return &mRaw; }

private:
  uv_loop_t mRaw{};
};

struct HandleMethod {
  auto IsActive() const noexcept -> bool { return uv_is_active(Inner()); }
  auto IsClosing() const noexcept -> bool { return uv_is_closing(Inner()); }
  auto Close(uv_close_cb cb) noexcept -> void { uv_close(Inner(), cb); }
  auto Ref() noexcept -> void { uv_ref(Inner()); }
  auto UnRef() noexcept -> void { uv_unref(Inner()); }
  auto HasRef() const noexcept -> bool { return uv_has_ref(Inner()); }
  static auto Size(uv_handle_type type) noexcept -> std::size_t { return uv_handle_size(type); }
  auto GetLoop() const noexcept -> uv_loop_t* { return uv_handle_get_loop(Inner()); }
  auto GetData() const noexcept -> void* { return uv_handle_get_data(Inner()); }
  auto SetData(void* data) noexcept -> void { return uv_handle_set_data(Inner(), data); }
  auto GetType() const noexcept -> uv_handle_type { return uv_handle_get_type(Inner()); }
  static auto TypeName(uv_handle_type type) noexcept -> char const* { return uv_handle_type_name(type); }

  auto Inner() noexcept -> uv_handle_t* { return std::bit_cast<uv_handle_t*>(this); }
  auto Inner() const noexcept -> uv_handle_t const* { return std::bit_cast<uv_handle_t*>(this); }
};

struct Req {
  auto Cancel() noexcept -> Error { return { uv_cancel(Inner()) }; }
  static auto Size(uv_req_type type) noexcept -> std::size_t { return uv_req_size(type); }
  auto SetData(void* data) noexcept -> void { return uv_req_set_data(Inner(), data); }
  auto GetData() const noexcept -> void* { return uv_req_get_data(Inner()); }
  auto GetType() const noexcept -> uv_req_type { return uv_req_get_type(Inner()); }
  static auto TypeName(uv_req_type type) noexcept -> char const* { return uv_req_type_name(type); }

  auto Inner() noexcept -> uv_req_t* { return std::bit_cast<uv_req_t*>(this); }
  auto Inner() const noexcept -> uv_req_t const* { return std::bit_cast<uv_req_t const*>(this); }
};

class Timer : public HandleMethod {
public:
  Timer() noexcept = default;
  auto Init(uv_loop_t* loop, void* userdata = nullptr) noexcept -> Error
  {
    SetData(userdata);
    return uv_timer_init(loop, Raw());
  }

  template <typename Rep, typename Period>
  auto Start(uv_timer_cb cb, std::chrono::duration<Rep, Period> timeout,
             std::chrono::duration<Rep, Period> repeat) noexcept -> Error
  {
    return { uv_timer_start(Raw(), cb, std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count(),
                            std::chrono::duration_cast<std::chrono::milliseconds>(repeat).count()) };
  }
  auto Stop() noexcept -> Error { return { uv_timer_stop(Raw()) }; }
  auto Again() noexcept -> Error { return { uv_timer_again(Raw()) }; }
  template <typename Rep, typename Period>
  auto SetRepeat(std::chrono::duration<Rep, Period> repeat) noexcept -> void
  {
    uv_timer_set_repeat(Raw(), std::chrono::duration_cast<std::chrono::milliseconds>(repeat).count());
  }

  auto GetRepeat() const noexcept -> std::chrono::milliseconds
  {
    return std::chrono::milliseconds(uv_timer_get_repeat(Raw()));
  }

  auto GetDueIn() const noexcept -> std::chrono::milliseconds
  {
    return std::chrono::milliseconds(uv_timer_get_due_in(Raw()));
  }

  auto Raw() noexcept -> uv_timer_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_timer_t const* { return &mRaw; }

private:
  uv_timer_t mRaw{};
};

class Prepare : public HandleMethod {
public:
  Prepare() noexcept = default;
  auto Init(uv_loop_t* loop, void* userdata = nullptr) noexcept -> void
  {
    SetData(userdata);
    auto r = uv_prepare_init(loop, Raw());
    assert(r == 0);
  }

  auto Start(uv_prepare_cb cb) noexcept -> void
  {
    assert(cb != nullptr);
    auto r = uv_prepare_start(Raw(), cb);
    assert(r == 0);
  }
  auto Stop() noexcept -> void
  {
    auto r = uv_prepare_stop(Raw());
    assert(r == 0);
  }

  auto Raw() noexcept -> uv_prepare_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_prepare_t const* { return &mRaw; }

private:
  uv_prepare_t mRaw{};
};

class Check : public HandleMethod {
public:
  Check() noexcept = default;
  auto Init(uv_loop_t* loop, void* userdata = nullptr) noexcept -> void
  {
    SetData(userdata);
    auto r = uv_check_init(loop, Raw());
    assert(r == 0);
  }

  auto Start(uv_check_cb cb) noexcept -> void
  {
    assert(cb != nullptr);
    auto r = uv_check_start(Raw(), cb);
    assert(r);
  }
  auto Stop() noexcept -> void
  {
    auto r = uv_check_stop(Raw());
    assert(r == 0);
  }

  auto Raw() noexcept -> uv_check_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_check_t const* { return &mRaw; }

private:
  uv_check_t mRaw{};
};

class Idle : public HandleMethod {
public:
  Idle() noexcept = default;
  auto Init(uv_loop_t* loop, void* userdata = nullptr) noexcept -> void
  {
    SetData(userdata);
    auto r = uv_idle_init(loop, Raw());
    assert(r == 0);
  }

  auto Start(uv_idle_cb cb) noexcept -> void
  {
    assert(cb != nullptr);
    auto r = uv_idle_start(Raw(), cb);
    assert(r == 0);
  }
  auto Stop() noexcept -> void
  {
    auto r = uv_idle_stop(Raw());
    assert(r == 0);
  }

  auto Raw() noexcept -> uv_idle_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_idle_t const* { return &mRaw; }

private:
  uv_idle_t mRaw{};
};

class Async : public HandleMethod {
public:
  Async() noexcept = default;
  auto Init(uv_loop_t* loop, uv_async_cb cb, void* userdata = nullptr) noexcept -> Error
  {
    SetData(userdata);
    return uv_async_init(loop, Raw(), cb);
  }
  auto Send() noexcept -> Error { return uv_async_send(Raw()); }

  auto Raw() noexcept -> uv_async_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_async_t const* { return &mRaw; }

private:
  uv_async_t mRaw{};
};

class Poll : public HandleMethod {
public:
  Poll() noexcept = default;
  auto Init(uv_loop_t* loop, int fd, void* userdata = nullptr) noexcept -> Error
  {
    SetData(userdata);
    return uv_poll_init(loop, Raw(), fd);
  }
  auto InitSocket(uv_loop_t* loop, uv_os_sock_t socket, void* userdata = nullptr) noexcept -> Error
  {
    SetData(userdata);
    return uv_poll_init_socket(loop, Raw(), socket);
  }
  auto Start(uv_poll_cb cb, int fd, int events) noexcept -> Error { return uv_poll_start(Raw(), events, cb); }
  auto Stop() noexcept -> Error { return uv_poll_stop(Raw()); }

  auto Raw() noexcept -> uv_poll_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_poll_t const* { return &mRaw; }

private:
  uv_poll_t mRaw{};
};

class Signal : public HandleMethod {
public:
  Signal() noexcept = default;
  auto Init(uv_loop_t* loop, void* userdata = nullptr) noexcept -> Error
  {
    SetData(userdata);
    return uv_signal_init(loop, Raw());
  }

  auto Start(uv_signal_cb cb, int signum) noexcept -> Error { return uv_signal_start(Raw(), cb, signum); }
  auto StartOneshot(uv_signal_cb cb, int signum) noexcept -> Error
  {
    return uv_signal_start_oneshot(Raw(), cb, signum);
  }
  auto Stop() noexcept -> Error { return uv_signal_stop(Raw()); }

  auto Raw() noexcept -> uv_signal_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_signal_t const* { return &mRaw; }

private:
  uv_signal_t mRaw{};
};

class Process : public HandleMethod {
public:
  Process() noexcept = default;
  static auto DisableStdioInheritance() noexcept -> void { uv_disable_stdio_inheritance(); }
  auto Spawn(uv_loop_t* loop, uv_process_options_t const* options, void* userdata = nullptr) noexcept -> Error
  {
    return uv_spawn(loop, Raw(), options);
  }
  auto Kill(int signum) noexcept -> Error { return uv_process_kill(Raw(), signum); }
  static auto Kill(int pid, int signum) noexcept -> Error { return uv_kill(pid, signum); }
  auto GetPid() const noexcept -> int { return uv_process_get_pid(Raw()); }

  auto Raw() noexcept -> uv_process_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_process_t const* { return &mRaw; }

private:
  uv_process_t mRaw{};
};

struct SteamMethod : public HandleMethod {
  auto Listen(int backlog, uv_connection_cb cb) noexcept -> Error { return uv_listen(Inner(), backlog, cb); }
  auto Accept(uv_stream_t* client) noexcept -> Error { return uv_accept(Inner(), client); }
  auto ReadStart(uv_alloc_cb alloc_cb, uv_read_cb read_cb) noexcept -> Error
  {
    return uv_read_start(Inner(), alloc_cb, read_cb);
  }
  auto ReadStop() noexcept -> Error { return uv_read_stop(Inner()); }
  // TODO uv_write/uv_write2
  auto TryWrite(uv_buf_t const bufs[], unsigned int nbufs) noexcept -> Error
  {
    return uv_try_write(Inner(), bufs, nbufs);
  }
  auto TryWrite2(uv_buf_t const bufs[], unsigned int nbufs, uv_stream_t* send_handle) -> Error
  {
    return uv_try_write2(Inner(), bufs, nbufs, send_handle);
  }
  auto IsReadable() const noexcept -> bool { return uv_is_readable(Inner()); }
  auto IsWritable() const noexcept -> bool { return uv_is_writable(Inner()); }
  auto SetBlocking(bool blocking) noexcept -> Error { return uv_stream_set_blocking(Inner(), blocking); }
  auto GetWriteQueueSize() const noexcept -> std::size_t { return uv_stream_get_write_queue_size(Inner()); }

  auto Inner() noexcept -> uv_stream_t* { return std::bit_cast<uv_stream_t*>(this); }
  auto Inner() const noexcept -> uv_stream_t const* { return std::bit_cast<uv_stream_t const*>(this); }
};

class Tcp : public SteamMethod {
public:
  Tcp() noexcept = default;
  auto Init(uv_loop_t* loop, void* userdata = nullptr) noexcept -> Error { return uv_tcp_init(loop, Raw()); }
  auto Init(uv_loop_t* loop, unsigned int flags, void* userdata = nullptr) noexcept -> Error
  {
    return uv_tcp_init_ex(loop, Raw(), flags);
  }

  auto Open(uv_os_sock_t sock) noexcept -> Error { return uv_tcp_open(Raw(), sock); }
  auto NoDelay(bool enable) noexcept -> Error { return uv_tcp_nodelay(Raw(), enable); }
  template <typename Rep, typename Period>
  auto KeepAlive(bool enable, std::chrono::duration<Rep, Period> delay) noexcept -> Error
  {
    return uv_tcp_keepalive(Raw(), enable, std::chrono::duration_cast<unsigned int>(delay).count());
  }
  auto SimultaneousAccepts(bool enable) noexcept -> Error { return uv_tcp_simultaneous_accepts(Raw(), enable); }
  auto Bind(const struct sockaddr* addr, unsigned int flags) noexcept -> Error
  {
    return uv_tcp_bind(Raw(), addr, flags);
  }
  auto GetSockName(struct sockaddr* name, int* namelen) noexcept -> Error
  {
    return uv_tcp_getsockname(Raw(), name, namelen);
  }
  auto GetPeerName(struct sockaddr* name, int* namelen) noexcept -> Error
  {
    return uv_tcp_getpeername(Raw(), name, namelen);
  }
  auto Connect(uv_connect_t* req, const struct sockaddr* addr, uv_connect_cb cb) noexcept -> Error
  {
    return uv_tcp_connect(req, Raw(), addr, cb);
  }
  auto CloseReset(uv_close_cb cb) noexcept -> Error { return uv_tcp_close_reset(Raw(), cb); }
  auto SocketPair(int type, int protocol, uv_os_sock_t socket_vector[2], int flags0, int flags1) noexcept -> Error
  {
    return uv_socketpair(type, protocol, socket_vector, flags0, flags1);
  }

  auto Raw() noexcept -> uv_tcp_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_tcp_t const* { return &mRaw; }

private:
  uv_tcp_t mRaw{};
};

class Pipe : public SteamMethod {
public:
  Pipe() noexcept = default;
  auto Init(uv_loop_t* loop, int ipc, void* userdata = nullptr) noexcept -> Error
  {
    return uv_pipe_init(loop, Raw(), ipc);
  }
  auto Open(uv_file file) noexcept -> Error { return uv_pipe_open(Raw(), file); }
  auto Bind(char const* name) noexcept -> Error { return uv_pipe_bind(Raw(), name); }
  auto Bind2(char const* name, std::size_t namelen, unsigned int flags) noexcept -> Error
  {
    return uv_pipe_bind2(Raw(), name, namelen, flags);
  }
  auto Connect(uv_connect_t* req, char const* name, uv_connect_cb cb) noexcept -> void
  {
    return uv_pipe_connect(req, Raw(), name, cb);
  }
  auto Connect(uv_connect_t* req, char const* name, std::size_t namelen, unsigned int flags, uv_connect_cb cb) noexcept
      -> Error
  {
    return uv_pipe_connect2(req, Raw(), name, namelen, flags, cb);
  }
  auto GetSockName(char* buffer, std::size_t* size) noexcept -> Error
  {
    return uv_pipe_getsockname(Raw(), buffer, size);
  }
  auto GetPeerName(char* buffer, std::size_t* size) noexcept -> Error
  {
    return uv_pipe_getpeername(Raw(), buffer, size);
  }
  auto PendingInstances(int count) noexcept -> void { uv_pipe_pending_instances(Raw(), count); }
  auto PendingCount() noexcept -> std::size_t { return uv_pipe_pending_count(Raw()); }
  auto PendingType() noexcept -> uv_handle_type { return uv_pipe_pending_type(Raw()); }
  auto Chmod(int flags) noexcept -> Error { return uv_pipe_chmod(Raw(), flags); }
  static auto New(uv_file fds[2], int read_flags, int write_flags) noexcept -> Error
  {
    return uv_pipe(fds, read_flags, write_flags);
  }

  auto Raw() noexcept -> uv_pipe_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_pipe_t const* { return &mRaw; }

private:
  uv_pipe_t mRaw{};
};

class Tty : public SteamMethod {
public:
  Tty() noexcept = default;
  auto Init(uv_loop_t* loop, uv_file fd, bool readable, void* userdata = nullptr) noexcept -> Error
  {
    return uv_tty_init(loop, Raw(), fd, readable);
  }
  auto SetMode(uv_tty_mode_t mode) noexcept -> Error { return uv_tty_set_mode(Raw(), mode); }
  auto GetWinsize(int* width, int* height) noexcept -> Error { return uv_tty_get_winsize(Raw(), width, height); }
  static auto ResetMode() noexcept -> Error { return uv_tty_reset_mode(); }
  static auto SetVtermState(uv_tty_vtermstate_t state) noexcept -> void { return uv_tty_set_vterm_state(state); }
  static auto GetVtermState(uv_tty_vtermstate_t* state) noexcept -> Error { return uv_tty_get_vterm_state(state); }

  auto Raw() noexcept -> uv_tty_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_tty_t const* { return &mRaw; }

private:
  uv_tty_t mRaw{};
};

class Udp : public SteamMethod {
public:
  Udp() noexcept = default;
  auto Init(uv_loop_t* loop, void* userdata = nullptr) noexcept -> Error { return uv_udp_init(loop, Raw()); }
  auto Init(uv_loop_t* loop, unsigned int flags, void* userdata = nullptr) noexcept -> Error
  {
    return uv_udp_init_ex(loop, Raw(), flags);
  }
  auto Open(uv_os_sock_t sock) noexcept -> Error { return uv_udp_open(Raw(), sock); }
  auto Bind(const struct sockaddr* addr, unsigned int flags) noexcept -> Error
  {
    return uv_udp_bind(Raw(), addr, flags);
  }
  auto Connect(const struct sockaddr* addr) noexcept -> Error { return uv_udp_connect(Raw(), addr); }
  auto GetPeerName(struct sockaddr* name, int* namelen) const noexcept -> Error
  {
    return uv_udp_getpeername(Raw(), name, namelen);
  }
  auto GetSockName(struct sockaddr* name, int* namelen) const noexcept -> Error
  {
    return uv_udp_getsockname(Raw(), name, namelen);
  }
  auto SetMembership(char const* multicast_addr, char const* interface_addr, uv_membership membership) -> Error
  {
    return uv_udp_set_membership(Raw(), multicast_addr, interface_addr, membership);
  }
  auto SetSourceMembership(char const* multicast_addr, char const* interface_addr, char const* source_addr,
                           uv_membership membership) noexcept -> Error
  {
    return uv_udp_set_source_membership(Raw(), multicast_addr, interface_addr, source_addr, membership);
  }
  auto SetMulticastLoop(bool on) noexcept -> int { return uv_udp_set_multicast_loop(Raw(), on); }
  auto SetMulticastTTL(int ttl) noexcept -> int { return uv_udp_set_multicast_ttl(Raw(), ttl); }
  auto SetMulticastInterface(char const* interface_addr) -> Error
  {
    return uv_udp_set_multicast_interface(Raw(), interface_addr);
  }
  auto SetBroadcast(bool on) -> Error { return uv_udp_set_broadcast(Raw(), on); }
  auto SetTTL(int ttl) -> Error { return uv_udp_set_ttl(Raw(), ttl); }
  auto Send(uv_udp_send_t* req, uv_buf_t const bufs[], unsigned int nbufs, const struct sockaddr* addr,
            uv_udp_send_cb send_cb) noexcept -> Error
  {
    return uv_udp_send(req, Raw(), bufs, nbufs, addr, send_cb);
  }
  auto TrySend(uv_buf_t const bufs[], unsigned int nbufs, const struct sockaddr* addr) noexcept -> Error
  {
    return uv_udp_try_send(Raw(), bufs, nbufs, addr);
  }
  auto RecvStart(uv_alloc_cb alloc_cb, uv_udp_recv_cb recv_cb) noexcept -> Error
  {
    return uv_udp_recv_start(Raw(), alloc_cb, recv_cb);
  }
  auto UsingRecvmmsg() noexcept -> Error { return uv_udp_using_recvmmsg(Raw()); }
  auto RecvStop() noexcept -> Error { return uv_udp_recv_stop(Raw()); }
  auto GetSendQueueSize() const noexcept -> std::size_t { return uv_udp_get_send_queue_size(Raw()); }
  auto GetSendQueueCount() const noexcept -> std::size_t { return uv_udp_get_send_queue_count(Raw()); }

  auto Raw() noexcept -> uv_udp_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_udp_t const* { return &mRaw; }

private:
  uv_udp_t mRaw{};
};

class FsEvent : HandleMethod {
public:
  FsEvent() noexcept = default;
  auto Init(uv_loop_t* loop) noexcept -> Error { return uv_fs_event_init(loop, Raw()); }
  auto Start(uv_fs_event_cb cb, char const* path, unsigned int flags) noexcept -> Error
  {
    return uv_fs_event_start(Raw(), cb, path, flags);
  }
  auto Stop() noexcept -> Error { return uv_fs_event_stop(Raw()); }
  auto GetPath(char* buffer, std::size_t* size) noexcept -> Error { return uv_fs_event_getpath(Raw(), buffer, size); }

  auto Raw() noexcept -> uv_fs_event_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_fs_event_t const* { return &mRaw; }

private:
  uv_fs_event_t mRaw{};
};

class FsPool : HandleMethod {
public:
  FsPool() noexcept = default;
  auto Init(uv_loop_t* loop) noexcept -> Error { return uv_fs_poll_init(loop, Raw()); }
  auto Start(uv_fs_poll_cb poll_cb, char const* path, unsigned int interval) noexcept -> Error
  {
    return uv_fs_poll_start(Raw(), poll_cb, path, interval);
  }
  auto Stop() noexcept -> Error { return uv_fs_poll_stop(Raw()); }
  auto GetPath(char* buffer, size_t* size) noexcept -> Error { return uv_fs_poll_getpath(Raw(), buffer, size); }

  auto Raw() noexcept -> uv_fs_poll_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_fs_poll_t const* { return &mRaw; }

private:
  uv_fs_poll_t mRaw{};
};

struct RequestMethod {
  static auto Size(uv_req_type type) noexcept -> std::size_t { return uv_req_size(type); }
  static auto TypeName(uv_req_type type) noexcept -> char const* { return uv_req_type_name(type); }

  auto Type() const noexcept -> uv_req_type { return uv_req_get_type(Inner()); }
  auto SetData(void* data) noexcept -> void { return uv_req_set_data(Inner(), data); }
  auto GetData() const noexcept -> void* { return uv_req_get_data(Inner()); }

  auto Cancel() noexcept -> Error { return { uv_cancel(Inner()) }; }

  auto Inner() noexcept -> uv_req_t* { return std::bit_cast<uv_req_t*>(this); }
  auto Inner() const noexcept -> uv_req_t const* { return std::bit_cast<uv_req_t const*>(this); }
};

class Fs : RequestMethod {
public:
  Fs() noexcept = default;
  auto Cleanup() noexcept -> void { uv_fs_req_cleanup(Raw()); }
  auto Close(uv_loop_t* loop, uv_file file, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_close(loop, Raw(), file, cb);
  }
  auto Open(uv_loop_t* loop, uv_file file, char const* path, int flags, int mode, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_open(loop, Raw(), path, flags, mode, cb);
  }
  auto Read(uv_loop_t* loop, uv_file file, uv_buf_t const bufs[], unsigned int nbufs, int64_t offset,
            uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_read(loop, Raw(), file, bufs, nbufs, offset, cb);
  }
  auto Unlink(uv_loop_t* loop, char const* path, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_unlink(loop, Raw(), path, cb);
  }
  auto Mkdir(uv_loop_t* loop, char const* path, int mode, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_mkdir(loop, Raw(), path, mode, cb);
  }
  auto Mktemp(uv_loop_t* loop, char const* tpl, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_mkstemp(loop, Raw(), tpl, cb);
  }
  auto Rmdir(uv_loop_t* loop, char const* path, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_rmdir(loop, Raw(), path, cb);
  }
  auto Scandir(uv_loop_t* loop, char const* path, int flags, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_scandir(loop, Raw(), path, flags, cb);
  }
  auto ScandirNext(uv_fs_t* req, uv_dirent_t* ent) noexcept -> Error { return uv_fs_scandir_next(req, ent); }
  auto Stat(uv_loop_t* loop, char const* path, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_stat(loop, Raw(), path, cb);
  }
  auto Lstat(uv_loop_t* loop, char const* path, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_lstat(loop, Raw(), path, cb);
  }
  auto Fstat(uv_loop_t* loop, uv_file file, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_fstat(loop, Raw(), file, cb);
  }
  auto Rename(uv_loop_t* loop, char const* path, char const* new_path, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_rename(loop, Raw(), path, new_path, cb);
  }
  auto Fsync(uv_loop_t* loop, uv_file file, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_fsync(loop, Raw(), file, cb);
  }
  auto Fdatasync(uv_loop_t* loop, uv_file file, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_fdatasync(loop, Raw(), file, cb);
  }
  auto Ftruncate(uv_loop_t* loop, uv_file file, int64_t offset, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_ftruncate(loop, Raw(), file, offset, cb);
  }
  auto Sendfile(uv_loop_t* loop, uv_file out_fd, uv_file in_fd, int64_t in_offset, size_t length, uv_fs_cb cb) noexcept
      -> Error
  {
    return uv_fs_sendfile(loop, Raw(), out_fd, in_fd, in_offset, length, cb);
  }
  auto Access(uv_loop_t* loop, char const* path, int mode, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_access(loop, Raw(), path, mode, cb);
  }
  auto Chmod(uv_loop_t* loop, char const* path, int mode, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_chmod(loop, Raw(), path, mode, cb);
  }
  auto Utime(uv_loop_t* loop, char const* path, double atime, double mtime, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_utime(loop, Raw(), path, atime, mtime, cb);
  }
  auto Futime(uv_loop_t* loop, uv_file file, double atime, double mtime, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_futime(loop, Raw(), file, atime, mtime, cb);
  }
  auto Link(uv_loop_t* loop, char const* path, char const* new_path, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_link(loop, Raw(), path, new_path, cb);
  }
  auto Symlink(uv_loop_t* loop, char const* path, char const* new_path, int flags, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_symlink(loop, Raw(), path, new_path, flags, cb);
  }
  auto Readlink(uv_loop_t* loop, char const* path, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_readlink(loop, Raw(), path, cb);
  }
  auto Chown(uv_loop_t* loop, char const* path, uv_uid_t uid, uv_gid_t gid, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_chown(loop, Raw(), path, uid, gid, cb);
  }
  auto Fchown(uv_loop_t* loop, uv_file file, uv_uid_t uid, uv_gid_t gid, uv_fs_cb cb) noexcept -> Error
  {
    return uv_fs_fchown(loop, Raw(), file, uid, gid, cb);
  }
  auto GetType() const noexcept -> uv_fs_type { return uv_fs_get_type(Raw()); }
  auto GetResult() const noexcept -> std::size_t { return uv_fs_get_result(Raw()); }
  auto GetSystemError() const noexcept -> int { return uv_fs_get_system_error(Raw()); }
  auto GetPtr() const noexcept -> void* { return uv_fs_get_ptr(Raw()); }
  auto GetPath() const noexcept -> char const* { return uv_fs_get_path(Raw()); }
  auto GetStatbuf() noexcept -> uv_stat_t* { return uv_fs_get_statbuf(Raw()); }
  static auto GetOsFhandle(int fd) noexcept -> uv_os_fd_t { return uv_get_osfhandle(fd); }
  static auto OpenOsFhandle(uv_os_fd_t os_fd) noexcept -> Error { return uv_open_osfhandle(os_fd); }

  auto Raw() noexcept -> uv_fs_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_fs_t const* { return &mRaw; }

private:
  uv_fs_t mRaw{};
};

class Work : RequestMethod {
private:
  Work() noexcept = default;
  auto QueueWork(uv_loop_t* loop, uv_work_cb work_cb, uv_after_work_cb after_work_cb) noexcept -> Error
  {
    return uv_queue_work(loop, Raw(), work_cb, after_work_cb);
  }
  auto Raw() noexcept -> uv_work_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_work_t const* { return &mRaw; }

public:
  uv_work_t mRaw{};
};

class GetAddrInfo : RequestMethod {
public:
  GetAddrInfo() noexcept = default;
  auto AddrInfo(uv_loop_t* loop, uv_getaddrinfo_cb getaddrinfo_cb, char const* node, char const* service,
                addrinfo const* hints) noexcept -> Error
  {
    return uv_getaddrinfo(loop, Raw(), getaddrinfo_cb, node, service, hints);
  }
  auto FreeAddrInfo(addrinfo* ai) noexcept -> void { uv_freeaddrinfo(ai); }

  auto Raw() noexcept -> uv_getaddrinfo_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_getaddrinfo_t const* { return &mRaw; }

private:
  uv_getaddrinfo_t mRaw{};
};

class GetNameInfo : RequestMethod {
public:
  GetNameInfo() noexcept = default;
  auto NameInfo(uv_loop_t* loop, uv_getnameinfo_cb getnameinfo_cb, sockaddr const* addr, int flags) noexcept -> Error
  {
    return uv_getnameinfo(loop, Raw(), getnameinfo_cb, addr, flags);
  }

  auto Raw() noexcept -> uv_getnameinfo_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_getnameinfo_t const* { return &mRaw; }

private:
  uv_getnameinfo_t mRaw{};
};

class SharedLib {
public:
  SharedLib() noexcept = default;
  auto Open(char const* filename) noexcept -> Error { return uv_dlopen(filename, &mRaw); }
  auto Close() noexcept -> void { uv_dlclose(&mRaw); }
  auto Sym(char const* name, void** ptr) noexcept -> Error { return uv_dlsym(&mRaw, name, ptr); }
  auto Error() const noexcept -> char const* { return uv_dlerror(&mRaw); }

  auto Raw() noexcept -> uv_lib_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_lib_t const* { return &mRaw; }

private:
  uv_lib_t mRaw{};
};

class Key {
public:
  Key() noexcept = default;
  auto Create() noexcept -> Error { return uv_key_create(Raw()); }
  auto Delete() noexcept -> void { uv_key_delete(Raw()); }
  auto Set(void* value) noexcept -> void { uv_key_set(Raw(), value); }
  auto Get() noexcept -> void* { return uv_key_get(Raw()); }

  auto Raw() noexcept -> uv_key_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_key_t const* { return &mRaw; }

private:
  uv_key_t mRaw{};
};
class Once {
public:
  Once() noexcept = default;
  auto Init(void (*callback)()) noexcept -> void { uv_once(Raw(), callback); }

  auto Raw() noexcept -> uv_once_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_once_t const* { return &mRaw; }

private:
  uv_once_t mRaw{};
};

class Thread {
public:
  Thread() noexcept = default;
  auto Create(uv_thread_cb entry, void* arg) noexcept -> Error { return uv_thread_create(Raw(), entry, arg); }
  auto Create(uv_thread_options_t* params, uv_thread_cb entry, void* arg) -> Error
  {
    return uv_thread_create_ex(Raw(), params, entry, arg);
  }
  auto SetAffinity(char* cpumask, char* oldmask, std::size_t mask_size) noexcept -> Error
  {
    return uv_thread_setaffinity(Raw(), cpumask, oldmask, mask_size);
  }
  auto GetAffinity(char* cpumask, std::size_t mask_size) noexcept -> Error
  {
    return uv_thread_getaffinity(Raw(), cpumask, mask_size);
  }
  static auto GetCpu() noexcept -> int { return uv_thread_getcpu(); }
  static auto Self() noexcept -> uv_thread_t { return uv_thread_self(); }
  auto Join() noexcept -> Error { return uv_thread_join(Raw()); }
  auto Equal(uv_thread_t const* other) noexcept -> bool { return uv_thread_equal(Raw(), other); }

  auto Raw() noexcept -> uv_thread_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_thread_t const* { return &mRaw; }

private:
  uv_thread_t mRaw{};
};

class Mutex {
public:
  Mutex() noexcept = default;
  auto Init() noexcept -> Error { return uv_mutex_init(Raw()); }
  auto Lock() noexcept -> void { return uv_mutex_lock(Raw()); }
  auto TryLock() noexcept -> Error { return uv_mutex_trylock(Raw()); }
  auto Unlock() noexcept -> void { return uv_mutex_unlock(Raw()); }
  auto Destroy() noexcept -> void { uv_mutex_destroy(Raw()); }

  auto Raw() noexcept -> uv_mutex_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_mutex_t const* { return &mRaw; }

private:
  uv_mutex_t mRaw{};
};

class RwLock {
public:
  RwLock() noexcept = default;

  auto Init() noexcept -> Error { return uv_rwlock_init(Raw()); }
  auto Destroy() noexcept -> void { uv_rwlock_destroy(Raw()); }

  auto RdLock() noexcept -> void { return uv_rwlock_rdlock(Raw()); }
  auto TryRdLock() noexcept -> Error { return uv_rwlock_tryrdlock(Raw()); }
  auto RdUnlock() noexcept -> void { return uv_rwlock_rdunlock(Raw()); }

  auto WrLock() noexcept -> void { return uv_rwlock_wrlock(Raw()); }
  auto TryWrLock() noexcept -> Error { return uv_rwlock_trywrlock(Raw()); }
  auto WrUnlock() noexcept -> void { return uv_rwlock_wrunlock(Raw()); }

  auto Raw() noexcept -> uv_rwlock_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_rwlock_t const* { return &mRaw; }

private:
  uv_rwlock_t mRaw{};
};

class Semaphore {
public:
  Semaphore() noexcept = default;
  auto Init(unsigned int value) noexcept -> Error { return uv_sem_init(Raw(), value); }
  auto Destroy() noexcept -> void { uv_sem_destroy(Raw()); }
  auto Post() noexcept -> void { uv_sem_post(Raw()); }
  auto TryWait() noexcept -> Error { return uv_sem_trywait(Raw()); }
  auto Wait() noexcept -> void { uv_sem_wait(Raw()); }

  auto Raw() noexcept -> uv_sem_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_sem_t const* { return &mRaw; }

private:
  uv_sem_t mRaw{};
};

class Cond {
public:
  Cond() noexcept = default;

  auto Init() noexcept -> Error { return uv_cond_init(Raw()); }
  auto Destroy() noexcept -> void { uv_cond_destroy(Raw()); }
  auto Signal() noexcept -> void { uv_cond_signal(Raw()); }
  auto Broadcast() noexcept -> void { uv_cond_broadcast(Raw()); }
  auto Wait(Mutex& mutex) noexcept -> void { uv_cond_wait(Raw(), mutex.Raw()); }
  auto TimedWait(Mutex& mutex, uint64_t timeout) noexcept -> Error
  {
    return uv_cond_timedwait(Raw(), mutex.Raw(), timeout);
  }

  auto Raw() noexcept -> uv_cond_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_cond_t const* { return &mRaw; }

private:
  uv_cond_t mRaw{};
};

class Barrier {
public:
  Barrier() noexcept = default;
  auto Init(unsigned int count) noexcept -> Error { return uv_barrier_init(Raw(), count); }
  auto Destroy() noexcept -> void { uv_barrier_destroy(Raw()); }
  auto Wait() noexcept -> void { uv_barrier_wait(Raw()); }

  auto Raw() noexcept -> uv_barrier_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_barrier_t const* { return &mRaw; }

private:
  uv_barrier_t mRaw{};
};

inline auto GuessHandle(uv_file file) noexcept -> uv_handle_type { return uv_guess_handle(file); }
inline auto ReplaceAllocator(uv_malloc_func malloc_func, uv_realloc_func realloc_func, uv_calloc_func calloc_func,
                             uv_free_func free_func) noexcept -> void
{
  uv_replace_allocator(malloc_func, realloc_func, calloc_func, free_func);
}
inline auto LibraryShutdown() noexcept -> void { uv_library_shutdown(); }
inline auto BufInit(char* base, std::size_t len) noexcept -> uv_buf_t { return uv_buf_init(base, len); }
inline auto SetupArgs(int argc, char* argv[]) noexcept -> char** { return uv_setup_args(argc, argv); }
inline auto GetProcessTitle(char* buffer, std::size_t size) noexcept -> Error
{
  return uv_get_process_title(buffer, size);
}
inline auto SetProcessTitle(char const* title) noexcept -> Error { return uv_set_process_title(title); }
inline auto ResidentSetMemory(size_t* rss) noexcept -> Error { return uv_resident_set_memory(rss); }
inline auto Uptime(double* uptime) noexcept -> Error { return uv_uptime(uptime); }
inline auto GetRUsage(uv_rusage_t* rusage) noexcept -> Error { return uv_getrusage(rusage); }
inline auto OsGetPPid() noexcept -> uv_pid_t { return uv_os_getppid(); }
inline auto AvailableParallelism() noexcept -> int { return uv_available_parallelism(); }
inline auto CPUInfo(uv_cpu_info_t** cpu_infos, int* count) noexcept -> Error { return uv_cpu_info(cpu_infos, count); }
inline auto FreeCPUInfo(uv_cpu_info_t* cpu_infos, int count) noexcept -> void { uv_free_cpu_info(cpu_infos, count); }
inline auto InterfaceAddresses(uv_interface_address_t** addresses, int* count) noexcept -> Error
{
  return uv_interface_addresses(addresses, count);
}
inline auto FreeInterfaceAddresses(uv_interface_address_t* addresses, int count) noexcept -> void
{
  uv_free_interface_addresses(addresses, count);
}
inline auto LoadAvg(double avg[3]) noexcept -> void { return uv_loadavg(avg); }
inline auto Ipv4Addr(char const* ip, int port, struct sockaddr_in* addr) noexcept -> Error
{
  return uv_ip4_addr(ip, port, addr);
}
inline auto Ipv6Addr(char const* ip, int port, struct sockaddr_in6* addr) noexcept -> Error
{
  return uv_ip6_addr(ip, port, addr);
}
inline auto Ipv4Name(struct sockaddr_in const* src, char* dst, size_t size) noexcept -> Error
{
  return uv_ip4_name(src, dst, size);
}
inline auto Ipv6Name(struct sockaddr_in6 const* src, char* dst, size_t size) noexcept -> Error
{
  return uv_ip6_name(src, dst, size);
}
inline auto IpName(struct sockaddr const* src, char* dst, size_t size) noexcept -> Error
{
  return uv_ip_name(src, dst, size);
}
inline auto InetNtop(int af, void const* src, char* dst, size_t size) noexcept -> Error
{
  return uv_inet_ntop(af, src, dst, size);
}
inline auto InetPton(int af, char const* src, void* dst) noexcept -> Error { return uv_inet_pton(af, src, dst); }
inline auto IfIndexToName(unsigned int index, char* buffer, size_t* size) noexcept -> Error
{
  return uv_if_indextoname(index, buffer, size);
}
inline auto IfIndexToIid(unsigned int index, char* buffer, size_t* size) noexcept -> Error
{
  return uv_if_indextoiid(index, buffer, size);
}
inline auto Exepath(char* buffer, size_t* size) noexcept -> Error { return uv_exepath(buffer, size); }
inline auto Cwd(char* buffer, size_t* size) noexcept -> Error { return uv_cwd(buffer, size); }
inline auto Chdir(char const* dir) noexcept -> Error { return uv_chdir(dir); }
inline auto OsHomeDir(char* buffer, size_t* size) noexcept -> Error { return uv_os_homedir(buffer, size); }
inline auto OsTmpDir(char* buffer, size_t* size) noexcept -> Error { return uv_os_tmpdir(buffer, size); }
inline auto OsGetPasswd(uv_passwd_t* pwd) noexcept -> Error { return uv_os_get_passwd(pwd); }
inline auto OsFreePasswd(uv_passwd_t* pwd) noexcept -> void { uv_os_free_passwd(pwd); }
inline auto GetFreeMemory() noexcept -> uint64_t { return uv_get_free_memory(); }
inline auto GetTotalMemory() noexcept -> uint64_t { return uv_get_total_memory(); }
inline auto GetConstrainedMemory() noexcept -> uint64_t { return uv_get_constrained_memory(); }
inline auto GetAvailableMemory() noexcept -> uint64_t { return uv_get_available_memory(); }
inline auto HrTime() noexcept -> uint64_t { return uv_hrtime(); }
inline auto ClockGetTime(uv_clock_id clock_id, uv_timespec64_t* ts) noexcept -> Error
{
  return uv_clock_gettime(clock_id, ts);
}
inline auto PrintAllHandles(uv_loop_t* loop, FILE* stream) noexcept -> void
{
  return uv_print_all_handles(loop, stream);
}
inline auto PrintActiveHandles(uv_loop_t* loop, FILE* stream) noexcept -> void
{
  return uv_print_active_handles(loop, stream);
}
inline auto OsEnviron(uv_env_item_t** env, int* count) noexcept -> Error { return uv_os_environ(env, count); }
inline auto OsFreeEnviron(uv_env_item_t* env, int count) noexcept -> void { uv_os_free_environ(env, count); }
inline auto OsSetEnv(char const* name, char const* value) noexcept -> Error { return uv_os_setenv(name, value); }
inline auto OsGetEnv(char const* name, char* buffer, size_t* size) noexcept -> Error
{
  return uv_os_getenv(name, buffer, size);
}
inline auto OsUnsetEnv(char const* name) noexcept -> Error { return uv_os_unsetenv(name); }
inline auto OsGetPriority(uv_pid_t pid, int* priority) noexcept -> Error { return uv_os_getpriority(pid, priority); }
inline auto OsSetPriority(uv_pid_t pid, int priority) noexcept -> Error { return uv_os_setpriority(pid, priority); }
inline auto OsUname(uv_utsname_t* buffer) noexcept -> Error { return uv_os_uname(buffer); }
inline auto Gettimeofday(uv_timeval64_t* tv) noexcept -> Error { return uv_gettimeofday(tv); }
inline auto Random(uv_loop_t* loop, uv_random_t* req, void* buf, size_t buflen, unsigned int flags,
                   uv_random_cb cb) noexcept -> Error
{
  return uv_random(loop, req, buf, buflen, flags, cb);
}
inline auto Sleep(unsigned int msec) noexcept -> void { return uv_sleep(msec); }

inline auto Utf16LengthAsWtf8(uint16_t const* utf16, ssize_t utf16_len) noexcept -> size_t
{
  return uv_utf16_length_as_wtf8(utf16, utf16_len);
}
inline auto Utf16ToWtf8(uint16_t const* utf16, ssize_t utf16_len, char** wtf8_ptr, size_t* wtf8_len_ptr) noexcept
    -> Error
{
  return uv_utf16_to_wtf8(utf16, utf16_len, wtf8_ptr, wtf8_len_ptr);
}
inline auto Wtf8LengthAsUtf16(char const* wtf8) noexcept -> size_t { return uv_wtf8_length_as_utf16(wtf8); }
inline auto Wtf8ToUtf16(char const* utf8, uint16_t* utf16, size_t utf16_len) noexcept -> void
{
  return uv_wtf8_to_utf16(utf8, utf16, utf16_len);
}

class Metrics {
public:
  Metrics() noexcept = default;
  auto IdleTime(uv_loop_t* loop) noexcept -> uint64_t { return uv_metrics_idle_time(loop); }
  auto Info(uv_loop_t* loop) noexcept -> Error { return uv_metrics_info(loop, Raw()); }

  auto Raw() noexcept -> uv_metrics_t* { return &mRaw; }
  auto Raw() const noexcept -> uv_metrics_t const* { return &mRaw; }

  auto LoopCount() const noexcept -> uint64_t { return mRaw.loop_count; }
  auto Events() const noexcept -> uint64_t { return mRaw.events; }
  auto EventsWaiting() const noexcept -> uint64_t { return mRaw.events_waiting; }

private:
  uv_metrics_t mRaw{};
};

template <typename From>
struct TypeMap;

#define DEFINE_TYPE_MAP_ENTRY(from, to)                                                                                \
  template <>                                                                                                          \
  struct TypeMap<from> {                                                                                               \
    static_assert(sizeof(from) == sizeof(to));                                                                         \
    using To = to;                                                                                                     \
  };

DEFINE_TYPE_MAP_ENTRY(uv_timer_t, Timer)
DEFINE_TYPE_MAP_ENTRY(uv_async_t, Async)
DEFINE_TYPE_MAP_ENTRY(uv_prepare_t, Prepare)
DEFINE_TYPE_MAP_ENTRY(uv_poll_t, Poll)
DEFINE_TYPE_MAP_ENTRY(uv_signal_t, Signal)
DEFINE_TYPE_MAP_ENTRY(uv_idle_t, Idle)
DEFINE_TYPE_MAP_ENTRY(uv_check_t, Check)
DEFINE_TYPE_MAP_ENTRY(uv_process_t, Process)
DEFINE_TYPE_MAP_ENTRY(uv_tcp_t, Tcp)
DEFINE_TYPE_MAP_ENTRY(uv_pipe_t, Pipe)
DEFINE_TYPE_MAP_ENTRY(uv_tty_t, Tty)
DEFINE_TYPE_MAP_ENTRY(uv_udp_t, Udp)
DEFINE_TYPE_MAP_ENTRY(uv_fs_event_t, FsEvent)
DEFINE_TYPE_MAP_ENTRY(uv_fs_poll_t, FsPool)
DEFINE_TYPE_MAP_ENTRY(uv_work_t, Work)
DEFINE_TYPE_MAP_ENTRY(uv_getaddrinfo_t, GetAddrInfo)
DEFINE_TYPE_MAP_ENTRY(uv_getnameinfo_t, GetNameInfo)
DEFINE_TYPE_MAP_ENTRY(uv_lib_t, SharedLib)
DEFINE_TYPE_MAP_ENTRY(uv_key_t, Key)
DEFINE_TYPE_MAP_ENTRY(uv_once_t, Once)
DEFINE_TYPE_MAP_ENTRY(uv_thread_t, Thread)
DEFINE_TYPE_MAP_ENTRY(uv_mutex_t, Mutex)
DEFINE_TYPE_MAP_ENTRY(uv_rwlock_t, RwLock)
DEFINE_TYPE_MAP_ENTRY(uv_cond_t, Cond)
DEFINE_TYPE_MAP_ENTRY(uv_barrier_t, Barrier)
DEFINE_TYPE_MAP_ENTRY(uv_fs_t, Fs)
DEFINE_TYPE_MAP_ENTRY(uv_loop_t, Loop)

#undef DEFINE_TYPE_MAP_ENTRY

template <typename T>
using MappedType = TypeMap<T>::To;

template <typename T>
inline auto Cast(T* ptr)
{
  return std::bit_cast<std::add_pointer_t<MappedType<T>>>(ptr);
}
} // namespace uv
