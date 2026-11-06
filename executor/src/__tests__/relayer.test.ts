import { ed25519 } from "@noble/curves/ed25519.js";
import { base64 } from "@scure/base";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SPONSOR_ACCOUNT_ID } from "../constants";
import {
  delegateActionSignHash,
  serializeDelegateAction,
  serializeFunctionCallAction,
} from "../protocol";
import { buildSignedDelegateAction } from "../relayer";
import type { RequestMessageJson } from "../walletContract";

const WALLET = "0saf343be226341c0eca7dba6d0b29d49bdff3ad03";
const MSG = { signer_id: WALLET, nonce: 7 } as unknown as RequestMessageJson;
const PROOF = "proof";

describe("buildSignedDelegateAction", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("builds and signs the delegate offline, with placeholder sender fields", async () => {
    const fetchSpy = vi.fn(() => {
      throw new Error("no network expected");
    });
    vi.stubGlobal("fetch", fetchSpy);

    const signed = base64.decode(await buildSignedDelegateAction(WALLET, MSG, PROOF));
    expect(fetchSpy).not.toHaveBeenCalled();

    // SignedDelegateAction = DelegateAction || 0 (ed25519) || 64-byte signature;
    // the DelegateAction ends with its ed25519 public key.
    const signature = signed.slice(-64);
    expect(signed[signed.length - 65]).toBe(0);
    const delegate = signed.slice(0, -65);
    const publicKey = delegate.slice(-32);

    const expected = serializeDelegateAction({
      senderId: SPONSOR_ACCOUNT_ID,
      receiverId: WALLET,
      actions: [
        serializeFunctionCallAction(
          "w_execute_signed",
          { msg: MSG, proof: PROOF },
          330_000_000_000_000n,
          1n,
        ),
      ],
      nonce: 0n,
      maxBlockHeight: 0n,
      publicKey,
    });
    expect(delegate).toEqual(expected);
    expect(ed25519.verify(signature, delegateActionSignHash(delegate), publicKey)).toBe(true);
  });
});
