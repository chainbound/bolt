"use client";

import Home from "@/components/home";
import { MetaMaskProvider } from "@metamask/sdk-react";
import React from "react";

export default function Main() {
  return (
    <React.StrictMode>
      <MetaMaskProvider
        debug={false}
        sdkOptions={{
          dappMetadata: {
            name: "Example React Dapp",
            url: window.location.href,
          },
          infuraAPIKey: process.env.INFURA_API_KEY,
          // Other options.
        }}
      >
        <Home />
      </MetaMaskProvider>
    </React.StrictMode>
  );
}
