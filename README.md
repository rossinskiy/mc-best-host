# mc-best-host

Find the fastest address to reach a Minecraft server from where you are.

Large servers sit behind networks and DDoS-protection proxies that hand out several addresses, and which
one you get can depend on who asks. This tool asks several public DNS resolvers where a server name points,
then times every address it finds with real connections and Minecraft status pings, and tells you which
one is fastest for you. It is one Python file with no dependencies (Python 3.8+).

## Use

```
python mc_best_host.py mc.example.net
python mc_best_host.py play.example.net:25570 --samples 12 --geo --trace
python mc_best_host.py mc.example.net --json
```

| Option | What it does |
|---|---|
| `--samples N` | measurements per address (default 8) |
| `--timeout S` | seconds to wait per connection (default 3) |
| `--resolver IP` | ask an extra DNS resolver (repeatable) |
| `--geo` | show where each address is (sends the server addresses, nothing else, to ip-api.com) |
| `--trace` | run traceroute to the best address |
| `--json` | machine-readable output |

## What it does

1. Looks up the `_minecraft._tcp` SRV record, because the game connects there first when it exists.
2. Asks 8 public resolvers plus your own for the address records and collects every distinct address.
3. For each address, measures plain TCP connect time and the Minecraft server-list ping (the same ping
   the game's server list uses), several times, and takes the median.
4. Ranks them and prints a `hosts` file line if a different address beats the one your DNS gives you.

Example (a server behind a protection proxy):

```
address           tcp ms  status  pong ms  jitter    ok  seen via
-----------------------------------------------------------------
50.114.4.194         4.6     3.8      3.3     0.6  5/5   9 resolvers (incl. this computer)  <== best
50.114.4.195         5.7     5.0      3.5     0.8  5/5   9 resolvers (incl. this computer)
50.114.4.250        71.9    72.1     71.1     0.6  5/5   9 resolvers (incl. this computer)
57.128.235.119     121.5   118.9    117.2     1.6  5/5   9 resolvers (incl. this computer)
```

## Limits (read this)

- It measures **you to the address it finds**. If the server is behind a proxy, the proxy often answers the
  status ping itself, so you only see you-to-proxy. Your in-game ping also includes the proxy-to-real-server
  leg, which no address choice can change. The tool tells you which case you are in: if the pong takes
  clearly longer than a plain connection, the ping was passed on to the real server and the number is a good
  estimate of your in-game ping.
- Pinning an address only helps if you join by **name**, not by typing a raw IP, and only if a different
  address is actually faster. Often your own DNS already gives you the best one and the tool says so.
- The biggest factor is usually distance. If the server is on another continent, the fix is not an address:
  it is running the client on a machine closer to the server.
- It uses `ip-api.com` only when you pass `--geo`.

## Pinning an address

Add one line to your hosts file (the tool prints it), and delete the line to undo:

- Windows: `C:\Windows\System32\drivers\etc\hosts` (edit as Administrator)
- Linux / macOS: `/etc/hosts` (edit as root)

```
50.114.4.194 connect.example.net
```
