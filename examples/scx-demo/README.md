# scx-demo

The SCX ceremony (WM-3) end to end, both sides in one process, with a real
`owm-rendezvous` relay spawned on an ephemeral port. No XMTP involved —
this demos the contact exchange alone: pairing code → mailbox claim →
SPAKE2 → transcript-bound signed cards → matching SAS → confirmed.

```sh
node demo.mjs   # needs Node >= 20 and cargo (builds the relay on first run)
```

Imports `@open-wallet-messaging/core` straight from the workspace (`packages/owm-core`).
