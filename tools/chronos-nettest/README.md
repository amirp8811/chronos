# chronos-nettest

A Chutney-like local smoke-test harness for CHRONOS.

It spawns two local `chronosd` relay processes using `cargo run -p chronosd`,
configures static routes, sends one CRP7 encrypted shard packet through:

```text
sender -> relay1 -> relay2 -> receiver
```

and verifies receiver delivery plus sender ACK.

Run from the workspace root:

```bash
cargo run -p chronos-nettest
```

You can override workspace discovery with:

```bash
CHRONOS_WORKSPACE=/path/to/chronos cargo run -p chronos-nettest
```
