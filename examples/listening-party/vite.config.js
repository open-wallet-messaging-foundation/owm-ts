// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Saxon Herschel Nicholls and the Open Wallet Messaging Foundation Authors
import { defineConfig, searchForWorkspaceRoot } from 'vite';
import basicSsl from '@vitejs/plugin-basic-ssl';

// Same setup as ../web-chat (see the comments there): HTTPS via basic-ssl
// because phones on the LAN need a secure context for OPFS + WebCrypto;
// no COOP/COEP needed (browser-sdk 7 uses no SharedArrayBuffer).
export default defineConfig({
  plugins: [basicSsl()],
  optimizeDeps: {
    // SDK loads workers/wasm via import.meta.url — must not be pre-bundled.
    exclude: ['@xmtp/browser-sdk', '@xmtp/wasm-bindings'],
  },
  server: {
    host: true, // listen on the LAN so phones can reach us
    fs: {
      // @open-wallet-messaging/core is imported by relative path from two levels up.
      allow: [searchForWorkspaceRoot(process.cwd())],
    },
  },
  preview: {
    host: true,
  },
});
