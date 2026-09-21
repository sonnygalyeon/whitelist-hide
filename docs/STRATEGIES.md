# Structured strategies

Strategies are configuration data, not shell scripts.

A strategy file currently describes:

- TCP and UDP port ranges;
- relative domain/IP list paths;
- a validated sequence of supported desynchronization stages.

Unknown TOML fields are rejected.

Current stage names are:

- `fake`
- `multi-split`
- `multi-disorder`
- `fake-split`
- `udp-length`
- `ip-fragment2`

This model deliberately does not accept arbitrary engine command-line fragments. A later compiler will translate a validated strategy into platform/engine-specific arguments.

The example at `examples/strategy.example.toml` is only data. It is not automatically applied to network traffic yet.
