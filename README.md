# tcprst-gadget

Trace the sequence of kernel function calls involved in the transmission of IPv4
TCP RST packets.

There are two flavours of the gadget:

- `tcprst-gadget`: It traces the `tcp_send_active_reset()`,
  `tcp_v4_send_reset()` and `nf_send_reset()` functions.
- `tcprst-gadget-without-nf`: It only traces the `tcp_send_active_reset()` and
  `tcp_v4_send_reset()` functions. This flavour is useful when the
  `nf_reject_ipv4` module is not loaded and the `nf_send_reset()` function is
  not available.

Check the [Implementation details](#implementation-details) section for more
information.

## Usage

The gadget is available in the GitHub Container Registry. You can run it using
the [`ig`](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/docs/ig.md) tool:

```bash
IG_EXPERIMENTAL=true sudo -E ig run ghcr.io/blanquicet/tcprst-gadget
```

```bash
IG_EXPERIMENTAL=true sudo -E ig run ghcr.io/blanquicet/tcprst-gadget-without-nf
```

## Implementation details

According to our research, there are three ways in the kernel to send a RST:

- `tcp_v{4|6}_send_reset`: It is used when we have to send a RST as a
  consequence of something wrong in an incoming packet. For instance:
  - The first packet is not a SYN as TCP always starts with a SYN.
  - The first packet is received on a closed port.
  - The host reaches the maximum amount of active TCP connections it is
    configured to support.
  - The client sends SYN to an already existing TCP endpoint, which means the
    same 5-tuple. The server will send a reset to the client.
- `tcp_send_active_reset`: Unlike `tcp_v{4|6}_send_reset`,
  `tcp_send_active_reset` is not in reply to incoming packet, but rather an
  active send. According to the comments in the kernel, this function is called
  _"when a process closes a file descriptor (either due to an explicit close()
  or as a byproduct of exit()'ing) and there was unread data in the receive
  queue."_. In addition, when the connection is idle for too long, this function
  is used to send a RST to close the connection.
- `nf_send_reset`: It is used by the `netfilter` packet filtering framework. One
  of the reason where it has to send a RST packet is when the user configures a
  rule with target `--reject-with tcp-reset`. For instance, `iptables -A INPUT
  -p tcp --dport 80 -j REJECT --reject-with tcp-reset`. **NOTE**: This function
  is available only if the `nf_reject_ipv4` module is loaded. It will be
  automatically loaded if the user configures a rule with target `REJECT`. Or it
  can be loaded manually using `modprobe nf_reject_ipv4`.

Some references:

- [1] [Reset tests](https://github.com/torvalds/linux/blob/9d1694dc91ce7b80bc96d6d8eaf1a1eca668d847/tools/testing/selftests/net/tcp_ao/rst.c#L45)
- [2] [`tcp_send_active_reset()` implementation](https://github.com/torvalds/linux/blob/v5.14/net/ipv4/tcp_output.c#L3426C1-L3431C60)

### Possible improvements

Once the image-based gadgets support user space code for post-processing data,
we could check if it is possible to only track `tcp_send_active_reset()`,
`tcp_v4_send_reset()` and `nf_send_reset`. And then, use the `bpf_get_stackid()`
helper to get the callers. Currently, it can't be done because the eBPF map
where the stack has to be written (`BPF_MAP_TYPE_STACK_TRACE`) can't be read
from the an eBPF program using `bpf_map_lookup_elem()`.

## Testing

> [!WARNING]
> The container and process information might not be correct if the
server and client are running in the same host (sharing the same kernel). Notice
it is the information of the process calling the function that sends the RST
which might be wrong. For instance, it happens when we try to connect to a
closed port from a client (e.g., `wget`). It will be the kernel who will reject
the connection with a RST as it is a closed port. However, when the gadget
captures the function call generating the reset and we try to retrieve the
process context using the `bpf_get_current_*()` helpers, they will incorrectly
return the `wget`'s process information while it should be the kernel one (pid
`0`, command `swapper/X` and none container name).

You can use the scripts in [tools/simulate-reset](./tools/simulate-reset/) to
test the gadget.

Start a HTTP server in background in host #1:

```bash
./tools/simulate-reset/server_in_bg.sh
```

Then, in host #2, run the client script. It will establish the connection and
then force it to be closed using a RST packet. Remember to configure the script
with the correct IP:

```bash
./tools/simulate-reset/client.sh
```

The gadget's output will look like this filtering by container `my-python`:

```text
$ IG_EXPERIMENTAL=true sudo -E ig run ghcr.io/blanquicet/tcprst-gadget -c my-python
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME CALLEE                     CALLER              SK… PID    COMM   SRC         DST
my-python             FUNC_TCP_SEND_ACTIVE_RESET FUNC_TCP_DISCONNECT 1   141531 python 127.0.0.1:0 127.0.0.1:8000
```

Use the JSON output format to make visible all the information the gadget is
able to capture:

```text
$ IG_EXPERIMENTAL=true sudo -E ig run ghcr.io/blanquicet/tcprst-gadget -c my-python -o jsonpretty
INFO[0000] Experimental features enabled
{
  "dst": {
    "v": 4,
    "kind": "",
    "port": 8000,
    "name": "",
    "addr": "127.0.0.1",
    "namespace": "",
    "proto": "TCP"
  },
  "runtime": {
    "runtimeName": "docker",
    "containerId": "0e7859b44b4e93d620108bda2c5103614fd6ff83a2798742f0ddd3fa3db3b3b7",
    "containerName": "my-python",
    "containerImageName": "python:3.7-alpine",
    "containerImageDigest": ""
  },
  "src": {
    "addr": "127.0.0.1",
    "name": "",
    "kind": "",
    "v": 4,
    "namespace": "",
    "port": 0,
    "proto": "TCP"
  },
  "k8s": {
    "node": "",
    "namespace": "",
    "pod": "",
    "container": "",
    "hostnetwork": false
  },
  "callee": "FUNC_TCP_SEND_ACTIVE_RESET",
  "callee_raw": 0,
  "caller": "FUNC_TCP_DISCONNECT",
  "caller_raw": 0,
  "sk_state": 1,
  "mntns_id": 4026532279,
  "netns_id": 4026532284,
  "pid": 51818,
  "tid": 51818,
  "uid": 0,
  "gid": 0,
  "comm": "python",
  "socket_mntns_id": 4026532279,
  "socket_netns_id": 4026532284,
  "socket_pid": 51818,
  "socket_tid": 51818,
  "socket_uid": 0,
  "socket_gid": 0,
  "socket_comm": "python"
}
```

Check the [gadget.yaml](./gadget/gadget.yaml) file to know what each field
represents.

## License

The user space code is licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
